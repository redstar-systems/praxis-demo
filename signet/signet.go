// Package signet drives a local private Bitcoin Signet (signetchallenge=51)
// to demonstrate operator-free Praxis witness-encrypted 2-of-2 Taproot vaults
// with an OP_CHECKSEQUENCEVERIFY (CSV) timelock refund leaf.
//
// Vault construction (following [Hio22] / Section 1 of the Praxis paper):
//   - Funds are locked in a two-leaf Tapscript tree under BIP-341's unspendable
//     nothing-up-my-sleeve internal key NUMS (50929b74...e803ac0, disabling key-path spends):
//       tr(NUMS, {multi_a(2, Depositor, Claimer), and_v(v:pk(Depositor_refund), older(6))})
//     * Leaf 1 (happy-path claim): <Depositor> OP_CHECKSIG <Claimer> OP_CHECKSIGADD 2 OP_NUMEQUAL
//     * Leaf 2 (timeout refund):   <Depositor_refund> OP_CHECKSIGVERIFY <6> OP_CHECKSEQUENCEVERIFY
//   - Both Depositor and Claimer keep their private keys LIVE in separate wallets
//     throughout; nobody is asked to trust that a key file was deleted.
//   - Depositor pre-signs ONLY its 1-of-2 partial PSBT for Leaf 1 paying Claimer,
//     seals that partial PSBT inside a Praxis ciphertext under the L2 burn statement,
//     and goes offline.
//   - Before 6 blocks elapse, Depositor cannot rug-pull via Leaf 1 (1-of-2 incomplete)
//     nor via Leaf 2 (rejected by consensus with non-BIP68-final); Claimer cannot
//     steal early via Leaf 1 without Praxis decryption. If Claimer ghosts without
//     burning on L2, Depositor reclaims the 1.0 sBTC via Leaf 2 once 6 blocks pass.
//
// Safety invariant: every RPC connection refuses mainnet ports (8332, 8382)
// and verifies getblockchaininfo().chain == "signet" before doing anything.
package signet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// BIP341NUMSInternalKey is the standard unspendable x-only internal key from
	// BIP-341 ("Constructing and spending Taproot outputs": lift_x(SHA256(uncompressed G))).
	BIP341NUMSInternalKey = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

	// VaultDepositSats is 1.00000000 sBTC locked into each 2-of-2 Taproot vault.
	VaultDepositSats int64 = 100_000_000
	// VaultFeeSats is 2,000 sats miner fee on the pre-signed BIP-342 Tapscript sweep tx.
	VaultFeeSats int64 = 2_000
	// VaultWithdrawSats is 0.99998000 sBTC delivered to Claimer's tb1p address.
	VaultWithdrawSats int64 = VaultDepositSats - VaultFeeSats
	// VaultCSVBlocks is the relative BIP-68 / OP_CHECKSEQUENCEVERIFY block delay
	// before Depositor can reclaim an unclaimed vault via Tapscript Leaf 2.
	VaultCSVBlocks uint32 = 6
)

// BIP-380 output script descriptor checksum alphabets.
const (
	descInputCharset    = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
	descChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

func descPolymod(c uint64, val int) uint64 {
	c0 := byte(c >> 35)
	c = ((c & 0x7ffffffff) << 5) ^ uint64(val)
	if c0&1 != 0 {
		c ^= 0xf5dee51989
	}
	if c0&2 != 0 {
		c ^= 0xa9fdca3312
	}
	if c0&4 != 0 {
		c ^= 0x1bab10e32d
	}
	if c0&8 != 0 {
		c ^= 0x3706b1677a
	}
	if c0&16 != 0 {
		c ^= 0x644d626ffd
	}
	return c
}

// DescriptorChecksum computes the 8-character BIP-380 checksum for a raw descriptor
// (including descriptors containing private keys like tprv, where getdescriptorinfo refuses).
func DescriptorChecksum(desc string) (string, error) {
	c := uint64(1)
	cls := 0
	clscount := 0
	for i := 0; i < len(desc); i++ {
		pos := strings.IndexByte(descInputCharset, desc[i])
		if pos < 0 {
			return "", fmt.Errorf("invalid descriptor character %q", desc[i])
		}
		c = descPolymod(c, pos&31)
		cls = cls*3 + (pos >> 5)
		clscount++
		if clscount == 3 {
			c = descPolymod(c, cls)
			cls = 0
			clscount = 0
		}
	}
	if clscount > 0 {
		c = descPolymod(c, cls)
	}
	for i := 0; i < 8; i++ {
		c = descPolymod(c, 0)
	}
	c ^= 1
	var out [8]byte
	for i := 0; i < 8; i++ {
		out[i] = descChecksumCharset[(c>>(5*(7-i)))&31]
	}
	return string(out[:]), nil
}

func withDescriptorChecksum(raw string) (string, error) {
	sum, err := DescriptorChecksum(raw)
	if err != nil {
		return "", err
	}
	return raw + "#" + sum, nil
}

// ChainStatus summarizes the live private Signet state across primary (and optional peer) nodes.
type ChainStatus struct {
	Mode        string // "local-signet", "custom-signet", or "ephemeral-signet"
	PrimaryRPC  string
	PeerRPC     string
	Chain       string
	Height      int
	PeerHeight  int
	BestHash    string
	StartedNode bool
}

// UnilateralAttempt records the result of either party trying to spend the 2-of-2
// claim leaf on their own (with their live private key intact).
type UnilateralAttempt struct {
	Actor            string // "depositor" or "claimer"
	WalletKeysLive   bool
	PartialSigned    bool
	FinalizableAlone bool
}

// CSVRefundAttempt records Depositor's attempt to broadcast the Leaf 2 OP_CSV
// refund transaction before VaultCSVBlocks confirmations have elapsed.
type CSVRefundAttempt struct {
	CSVBlocks        uint32
	LeafFinalized    bool   // true: Depositor holds the sole key for Leaf 2
	MempoolAllowed   bool   // false before VaultCSVBlocks confirmations
	RejectReason     string // e.g. "non-BIP68-final"
	SignedRefundTxID string
}

// LockedVault holds the public parameters of a funded 2-of-2 Taproot
// (tr(NUMS, multi_a(2, Depositor, Claimer))) vault on Signet, plus Depositor's
// 1-of-2 partial PSBT bytes to seal inside a Praxis ciphertext.
type LockedVault struct {
	VaultAddress         string
	PublicDescriptor     string
	DepositTxID          string
	DepositVout          int
	DepositBlock         int
	DepositBlockHash     string
	VaultScriptHex       string
	RecipientAddress     string
	DepositSats          int64
	WithdrawSats         int64
	FeeSats              int64
	ExpectedSweepTxID    string
	DepositorSigHex      string // Depositor's 64-byte BIP-340 Tapscript signature
	DepositorPartialPSBT []byte // Raw binary 1-of-2 PSBT (sealed into Praxis CT, then zeroed)

	DepositorWallet string // Kept live in Bitcoin Core to prove unilateral rug-pull still fails
	ClaimerWallet   string // Kept live in Bitcoin Core to co-sign once Praxis decrypts
}

// OutPoint returns "<deposit_txid>:<vout>".
func (v LockedVault) OutPoint() string {
	return fmt.Sprintf("%s:%d", v.DepositTxID, v.DepositVout)
}

// SweepSettlement records the on-chain confirmation of a 2-of-2 co-signed withdrawal.
type SweepSettlement struct {
	SweepTxID       string
	WitnessItems    int // 4 items for multi_a(2): [sig_claimer, sig_depositor, tapscript, control_block]
	TxBytes         int
	BlockHeight     int
	BlockHash       string
	PeerSynced      bool
	PeerBlockHeight int
	VaultSpent      bool
	RecipientSats   int64
}

// Env represents an active connection to a local private Bitcoin Signet.
type Env struct {
	Mode        string
	Primary     *RPCClient
	Peer        *RPCClient // optional second local signet peer node
	PrimaryData string
	StartedNode bool

	sessionWallets []string
	ephemeralDir   string
	ephemeralCmd   *exec.Cmd
}

// RPCClient is a minimal JSON-RPC 2.0 HTTP client for Bitcoin Core on 127.0.0.1.
type RPCClient struct {
	HostPort   string
	CookiePath string
	AuthHeader string
	HTTP       *http.Client
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("bitcoin rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// NewRPCClient constructs a loopback-only Signet RPC client, rejecting mainnet ports.
func NewRPCClient(hostPort, cookiePath, userPass string) (*RPCClient, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("invalid rpc host:port %q: %w", hostPort, err)
	}
	if host != "127.0.0.1" && host != "localhost" {
		return nil, fmt.Errorf("refusing non-loopback bitcoin rpc host %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("invalid rpc port %q", portStr)
	}
	if port == 8332 || port == 8333 || port == 8382 || port == 8383 {
		return nil, fmt.Errorf("safety block: port %d is a Bitcoin mainnet port; refusing connection", port)
	}
	c := &RPCClient{
		HostPort:   hostPort,
		CookiePath: cookiePath,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
	}
	if userPass != "" {
		c.AuthHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
	}
	return c, nil
}

func (c *RPCClient) authHeader() (string, error) {
	if c.AuthHeader != "" {
		return c.AuthHeader, nil
	}
	raw, err := os.ReadFile(c.CookiePath)
	if err != nil {
		return "", err
	}
	creds := strings.TrimSpace(string(raw))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)), nil
}

// Call invokes method on bitcoind (optionally scoped to wallet) and JSON-decodes result into out.
func (c *RPCClient) Call(wallet, method string, params []any, out any) error {
	if params == nil {
		params = []any{}
	}
	auth, err := c.authHeader()
	if err != nil {
		return err
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return err
	}
	url := "http://" + c.HostPort
	if wallet != "" {
		url += "/wallet/" + wallet
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var parsed rpcResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return fmt.Errorf("rpc %s status %d: %w", method, resp.StatusCode, err)
	}
	if parsed.Error != nil {
		return parsed.Error
	}
	if out != nil && len(parsed.Result) > 0 && string(parsed.Result) != "null" {
		if err := json.Unmarshal(parsed.Result, out); err != nil {
			return fmt.Errorf("decode %s: %w", method, err)
		}
	}
	return nil
}

type blockchainInfo struct {
	Chain         string `json:"chain"`
	Blocks        int    `json:"blocks"`
	BestBlockHash string `json:"bestblockhash"`
}

func (c *RPCClient) verifySignet() (blockchainInfo, error) {
	var info blockchainInfo
	if err := c.Call("", "getblockchaininfo", nil, &info); err != nil {
		return info, err
	}
	if info.Chain != "signet" {
		return info, fmt.Errorf("safety block: expected chain=\"signet\", got %q on %s", info.Chain, c.HostPort)
	}
	return info, nil
}

// FindBitcoind locates a local Bitcoin Core daemon binary via PRAXIS_BITCOIND,
// standard system PATH, or common Homebrew/system install paths.
func FindBitcoind(_ bool) (string, error) {
	var candidates []string
	if envBin := os.Getenv("PRAXIS_BITCOIND"); envBin != "" {
		candidates = append(candidates, envBin)
	}
	if p, err := exec.LookPath("bitcoind"); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates,
		"/opt/homebrew/bin/bitcoind",
		"/usr/local/bin/bitcoind",
		"/usr/bin/bitcoind",
	)
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("bitcoind binary not found (install Bitcoin Core or set PRAXIS_BITCOIND)")
}

// ConnectAttachOrStart connects to an explicit RPC, or to a local two-node private
// Signet pointed to by PRAXIS_SIGNET_DIR (:38401 / :38402), falling back to an
// isolated ephemeral signetchallenge=51 node.
func ConnectAttachOrStart(explicitRPC, explicitCookie string) (*Env, error) {
	if explicitRPC != "" {
		cli, err := NewRPCClient(explicitRPC, explicitCookie, "")
		if err != nil {
			return nil, err
		}
		if _, err := cli.verifySignet(); err != nil {
			return nil, err
		}
		env := &Env{
			Mode:    "custom-signet",
			Primary: cli,
		}
		if err := env.ensureWallet("miner"); err != nil {
			return nil, err
		}
		return env, nil
	}

	if signetDir := os.Getenv("PRAXIS_SIGNET_DIR"); signetDir != "" {
		nodeAConf := filepath.Join(signetDir, "state", "a", "node", "bitcoin.conf")
		if _, err := os.Stat(nodeAConf); err == nil {
			return ConnectLocalSignet(signetDir)
		}
	}
	return StartEphemeral()
}

// ConnectLocalSignet attaches to a local two-node private Signet (:38401 and :38402),
// starting either bitcoind cleanly if currently stopped and syncing their tips.
func ConnectLocalSignet(signetDir string) (*Env, error) {
	nodeADir := filepath.Join(signetDir, "state", "a", "node")
	nodeBDir := filepath.Join(signetDir, "state", "b", "node")
	cookieA := filepath.Join(nodeADir, "signet", ".cookie")
	cookieB := filepath.Join(nodeBDir, "signet", ".cookie")

	cliA, err := NewRPCClient("127.0.0.1:38401", cookieA, "")
	if err != nil {
		return nil, err
	}
	cliB, err := NewRPCClient("127.0.0.1:38402", cookieB, "")
	if err != nil {
		return nil, err
	}

	startedAny := false
	if _, err := cliA.verifySignet(); err != nil {
		bin, berr := FindBitcoind(true)
		if berr != nil {
			return nil, fmt.Errorf("local signet node-a is stopped and bitcoind not found: %w", berr)
		}
		pid, serr := spawnDetachedBitcoind(bin, nodeADir, filepath.Join(signetDir, "state", "node-a.log"))
		if serr != nil {
			return nil, serr
		}
		updateSignetPids(filepath.Join(signetDir, "state", "pids.json"), "node-a", pid)
		if err := waitSignetReady(cliA, 20*time.Second); err != nil {
			return nil, fmt.Errorf("waiting for local signet node-a: %w", err)
		}
		startedAny = true
	}

	if _, stErr := os.Stat(filepath.Join(nodeBDir, "bitcoin.conf")); stErr == nil {
		if _, err := cliB.verifySignet(); err != nil {
			if bin, berr := FindBitcoind(true); berr == nil {
				if pid, serr := spawnDetachedBitcoind(bin, nodeBDir, filepath.Join(signetDir, "state", "node-b.log")); serr == nil {
					updateSignetPids(filepath.Join(signetDir, "state", "pids.json"), "node-b", pid)
					_ = waitSignetReady(cliB, 20*time.Second)
					startedAny = true
				}
			}
		}
	} else {
		cliB = nil
	}

	env := &Env{
		Mode:        "local-signet",
		Primary:     cliA,
		Peer:        cliB,
		PrimaryData: nodeADir,
		StartedNode: startedAny,
	}
	if err := env.ensureWallet("miner"); err != nil {
		return nil, err
	}
	env.waitForPeerSync(8 * time.Second)
	return env, nil
}

func spawnDetachedBitcoind(bin, datadir, logPath string) (int, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()
	cmd := exec.Command(bin, "-datadir="+datadir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

func updateSignetPids(pidsPath, key string, pid int) {
	pids := map[string]int{}
	if raw, err := os.ReadFile(pidsPath); err == nil {
		_ = json.Unmarshal(raw, &pids)
	}
	pids[key] = pid
	if out, err := json.Marshal(pids); err == nil {
		_ = os.WriteFile(pidsPath, out, 0o600)
	}
}

func waitSignetReady(cli *RPCClient, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := cli.verifySignet(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(150 * time.Millisecond)
	}
	return lastErr
}

// StartEphemeral launches an isolated private Signet (signetchallenge=51) bitcoind
// in a temporary directory, mines 101 blocks so coinbase UTXOs mature, and returns
// an Env whose Close() stops bitcoind and deletes the temporary datadir.
func StartEphemeral() (*Env, error) {
	bin, err := FindBitcoind(false)
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "praxis-signet-*")
	if err != nil {
		return nil, err
	}
	rpcPort, err := freePort()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	p2pPort, err := freePort()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	var saltBytes [16]byte
	var passBytes [24]byte
	_, _ = rand.Read(saltBytes[:])
	_, _ = rand.Read(passBytes[:])
	salt := hex.EncodeToString(saltBytes[:])
	pass := hex.EncodeToString(passBytes[:])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(pass))
	digest := hex.EncodeToString(mac.Sum(nil))

	conf := fmt.Sprintf(
		"signet=1\n[signet]\nsignetchallenge=51\nrpcport=%d\nport=%d\n"+
			"bind=127.0.0.1\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"+
			"server=1\ndnsseed=0\nfixedseeds=0\ndiscover=0\ntxindex=1\n"+
			"fallbackfee=0.0002\nrpcauth=praxis:%s$%s\n",
		rpcPort, p2pPort, salt, digest,
	)
	if err := os.WriteFile(filepath.Join(tmpDir, "bitcoin.conf"), []byte(conf), 0o600); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	logFile, err := os.OpenFile(filepath.Join(tmpDir, "bitcoind.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	cmd := exec.Command(bin, "-datadir="+tmpDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	_ = logFile.Close()

	cli, err := NewRPCClient(
		fmt.Sprintf("127.0.0.1:%d", rpcPort),
		filepath.Join(tmpDir, "signet", ".cookie"),
		"praxis:"+pass,
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := waitSignetReady(cli, 20*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("ephemeral signet failed to start: %w", err)
	}

	env := &Env{
		Mode:         "ephemeral-signet",
		Primary:      cli,
		PrimaryData:  tmpDir,
		StartedNode:  true,
		ephemeralDir: tmpDir,
		ephemeralCmd: cmd,
	}
	var createRes map[string]any
	if err := cli.Call("", "createwallet", []any{"miner", false, false, "", false, true, false}, &createRes); err != nil {
		_ = env.Close()
		return nil, fmt.Errorf("create miner wallet: %w", err)
	}
	if _, _, err := env.MineBlocks(101); err != nil {
		_ = env.Close()
		return nil, fmt.Errorf("mine initial 101 signet blocks: %w", err)
	}
	return env, nil
}

// Close cleans up session demo wallets (at process exit, AFTER all checks/withdrawals
// have completed) and shuts down any ephemeral Signet node.
func (e *Env) Close() error {
	if e == nil {
		return nil
	}
	for _, w := range e.sessionWallets {
		var unloadRes map[string]any
		_ = e.Primary.Call("", "unloadwallet", []any{w, false}, &unloadRes)
		if e.PrimaryData != "" {
			_ = os.RemoveAll(filepath.Join(e.PrimaryData, "signet", "wallets", w))
			_ = os.RemoveAll(filepath.Join(e.PrimaryData, "signet", w))
		}
	}
	e.sessionWallets = nil

	if e.ephemeralDir == "" {
		return nil
	}
	var stopMsg string
	_ = e.Primary.Call("", "stop", nil, &stopMsg)
	if e.ephemeralCmd != nil && e.ephemeralCmd.Process != nil {
		done := make(chan error, 1)
		go func() { done <- e.ephemeralCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = e.ephemeralCmd.Process.Kill()
		}
	}
	return os.RemoveAll(e.ephemeralDir)
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (e *Env) ensureWallet(name string) error {
	var loaded []string
	if err := e.Primary.Call("", "listwallets", nil, &loaded); err != nil {
		return err
	}
	for _, w := range loaded {
		if w == name {
			return nil
		}
	}
	var dirInfo struct {
		Wallets []struct {
			Name string `json:"name"`
		} `json:"wallets"`
	}
	if err := e.Primary.Call("", "listwalletdir", nil, &dirInfo); err == nil {
		for _, w := range dirInfo.Wallets {
			if w.Name == name {
				var res map[string]any
				return e.Primary.Call("", "loadwallet", []any{name, false}, &res)
			}
		}
	}
	var res map[string]any
	return e.Primary.Call("", "createwallet", []any{name, false, false, "", false, true, false}, &res)
}

// Status queries the current chain height and best block hash on Primary (and Peer if present).
func (e *Env) Status() (ChainStatus, error) {
	info, err := e.Primary.verifySignet()
	if err != nil {
		return ChainStatus{}, err
	}
	st := ChainStatus{
		Mode:        e.Mode,
		PrimaryRPC:  e.Primary.HostPort,
		Chain:       info.Chain,
		Height:      info.Blocks,
		PeerHeight:  -1,
		BestHash:    info.BestBlockHash,
		StartedNode: e.StartedNode,
	}
	if e.Peer != nil {
		st.PeerRPC = e.Peer.HostPort
		if pInfo, err := e.Peer.verifySignet(); err == nil {
			st.PeerHeight = pInfo.Blocks
		}
	}
	return st, nil
}

// MineBlocks mines n private Signet blocks (challenge 51) to the miner wallet.
func (e *Env) MineBlocks(n int) (height int, bestHash string, err error) {
	var addr string
	if err := e.Primary.Call("miner", "getnewaddress", []any{"", "bech32m"}, &addr); err != nil {
		return 0, "", err
	}
	rem := n
	for rem > 0 {
		batch := min(rem, 8)
		var hashes []string
		if err := e.Primary.Call("", "generatetoaddress", []any{batch, addr, 100_000_000}, &hashes); err != nil {
			return 0, "", err
		}
		if len(hashes) > 0 {
			bestHash = hashes[len(hashes)-1]
			rem -= len(hashes)
		}
	}
	if err := e.Primary.Call("", "getblockcount", nil, &height); err != nil {
		return 0, "", err
	}
	e.waitForPeerSync(5 * time.Second)
	return height, bestHash, nil
}

func (e *Env) waitForPeerSync(timeout time.Duration) bool {
	if e.Peer == nil {
		return false
	}
	var target int
	if err := e.Primary.Call("", "getblockcount", nil, &target); err != nil {
		return false
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var peerH int
		if err := e.Peer.Call("", "getblockcount", nil, &peerH); err == nil && peerH >= target {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// extractTrKeyExprBranch pulls the inner key expression "[fp/86h/1h/0h]tprv.../<branch>/*"
// or "[fp/86h/1h/0h]tpub.../<branch>/*" from a wallet's BIP-86 Taproot descriptor.
func (e *Env) extractTrKeyExprBranch(wallet string, branch int, priv bool) (string, error) {
	var res struct {
		Descriptors []struct {
			Desc string `json:"desc"`
		} `json:"descriptors"`
	}
	if err := e.Primary.Call(wallet, "listdescriptors", []any{priv}, &res); err != nil {
		return "", err
	}
	needle := fmt.Sprintf("/%d/*", branch)
	for _, d := range res.Descriptors {
		if strings.HasPrefix(d.Desc, "tr(") && strings.Contains(d.Desc, needle) {
			end := strings.LastIndex(d.Desc, ")#")
			if end > 3 {
				return d.Desc[3:end], nil
			}
		}
	}
	return "", fmt.Errorf("no branch %d tr(...) descriptor in wallet %s", branch, wallet)
}

func (e *Env) importVaultDescriptor(wallet, rawDesc string) error {
	descWithSum, err := withDescriptorChecksum(rawDesc)
	if err != nil {
		return err
	}
	req := []map[string]any{{
		"desc":      descWithSum,
		"timestamp": "now",
		"range":     []int{0, 2},
	}}
	var res []struct {
		Success bool `json:"success"`
		Error   *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := e.Primary.Call(wallet, "importdescriptors", []any{req}, &res); err != nil {
		return err
	}
	if len(res) == 0 || !res[0].Success {
		msg := "unknown importdescriptors failure"
		if len(res) > 0 && res[0].Error != nil {
			msg = res[0].Error.Message
		}
		return errors.New(msg)
	}
	return nil
}

// LockTaprootVault creates an operator-free 2-of-2 Tapscript vault on Signet:
//  1. Creates TWO independent live wallets: Depositor and Claimer (both retain
//     their private keys—nobody is trusted to delete a key).
//  2. Derives tr(NUMS, multi_a(2, Depositor, Claimer)) so key-path spends are
//     impossible and spending requires BOTH Depositor's and Claimer's Schnorr sigs.
//  3. Funds the 2-of-2 P2TR vault with 1.00000000 sBTC and mines 1 Signet block.
//  4. Depositor signs ONLY its 1-of-2 partial PSBT paying Claimer 0.99998000 sBTC,
//     returning the raw partial PSBT bytes to encrypt inside Praxis.
func (e *Env) LockTaprootVault() (*LockedVault, error) {
	if _, err := e.Primary.verifySignet(); err != nil {
		return nil, err
	}
	var nonce [5]byte
	_, _ = rand.Read(nonce[:])
	tag := hex.EncodeToString(nonce[:])
	depWallet := "praxis-dep-" + tag
	clmWallet := "praxis-clm-" + tag

	for _, w := range []string{depWallet, clmWallet} {
		var res map[string]any
		if err := e.Primary.Call("", "createwallet", []any{w, false, false, "", false, true, false}, &res); err != nil {
			return nil, fmt.Errorf("create wallet %s: %w", w, err)
		}
		e.sessionWallets = append(e.sessionWallets, w)
	}

	dep0Priv, err := e.extractTrKeyExprBranch(depWallet, 0, true)
	if err != nil {
		return nil, err
	}
	dep0Pub, err := e.extractTrKeyExprBranch(depWallet, 0, false)
	if err != nil {
		return nil, err
	}
	dep1Priv, err := e.extractTrKeyExprBranch(depWallet, 1, true)
	if err != nil {
		return nil, err
	}
	dep1Pub, err := e.extractTrKeyExprBranch(depWallet, 1, false)
	if err != nil {
		return nil, err
	}
	clm0Priv, err := e.extractTrKeyExprBranch(clmWallet, 0, true)
	if err != nil {
		return nil, err
	}
	clm0Pub, err := e.extractTrKeyExprBranch(clmWallet, 0, false)
	if err != nil {
		return nil, err
	}

	rawForDep := fmt.Sprintf("tr(%s,{multi_a(2,%s,%s),and_v(v:pk(%s),older(%d))})",
		BIP341NUMSInternalKey, dep0Priv, clm0Pub, dep1Priv, VaultCSVBlocks)
	rawForClm := fmt.Sprintf("tr(%s,{multi_a(2,%s,%s),and_v(v:pk(%s),older(%d))})",
		BIP341NUMSInternalKey, dep0Pub, clm0Priv, dep1Pub, VaultCSVBlocks)
	rawPub := fmt.Sprintf("tr(%s,{multi_a(2,%s,%s),and_v(v:pk(%s),older(%d))})",
		BIP341NUMSInternalKey, dep0Pub, clm0Pub, dep1Pub, VaultCSVBlocks)

	if err := e.importVaultDescriptor(depWallet, rawForDep); err != nil {
		return nil, fmt.Errorf("import 2-of-2 descriptor into depositor: %w", err)
	}
	if err := e.importVaultDescriptor(clmWallet, rawForClm); err != nil {
		return nil, fmt.Errorf("import 2-of-2 descriptor into claimer: %w", err)
	}

	pubDesc, err := withDescriptorChecksum(rawPub)
	if err != nil {
		return nil, err
	}
	var derived []string
	if err := e.Primary.Call("", "deriveaddresses", []any{pubDesc, []int{0, 0}}, &derived); err != nil || len(derived) == 0 {
		return nil, fmt.Errorf("derive 2-of-2 vault address: %w", err)
	}
	vaultAddr := derived[0]

	var recipientAddr string
	if err := e.Primary.Call(clmWallet, "getnewaddress", []any{"", "bech32m"}, &recipientAddr); err != nil {
		return nil, fmt.Errorf("claimer recipient address: %w", err)
	}

	// Fund the 2-of-2 Taproot vault with 1.00000000 sBTC and confirm in 1 Signet block.
	var depositTxID string
	if err := e.Primary.Call("miner", "sendtoaddress", []any{vaultAddr, json.Number("1.00000000")}, &depositTxID); err != nil {
		return nil, fmt.Errorf("fund 2-of-2 vault: %w", err)
	}
	depHeight, depBlockHash, err := e.MineBlocks(1)
	if err != nil {
		return nil, fmt.Errorf("mine deposit block: %w", err)
	}

	var depTx struct {
		Vout []struct {
			N            int     `json:"n"`
			Value        float64 `json:"value"`
			ScriptPubKey struct {
				Hex     string `json:"hex"`
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if err := e.Primary.Call("", "getrawtransaction", []any{depositTxID, true}, &depTx); err != nil {
		return nil, fmt.Errorf("get deposit tx: %w", err)
	}
	depositVout := -1
	var vaultScriptHex string
	for _, out := range depTx.Vout {
		if out.ScriptPubKey.Address == vaultAddr {
			depositVout = out.N
			vaultScriptHex = out.ScriptPubKey.Hex
			break
		}
	}
	if depositVout < 0 {
		return nil, fmt.Errorf("2-of-2 vault output %s not found in tx %s", vaultAddr, depositTxID)
	}

	// Construct the unsigned Leaf-1 withdrawal PSBT paying Claimer 0.99998000 sBTC.
	// Setting sequence=0xfffffffe disables BIP-68 relative locktime so Miniscript
	// targets Leaf 1 (multi_a(2, Depositor, Claimer)) rather than Leaf 2 (older(6)).
	inputs := []map[string]any{{"txid": depositTxID, "vout": depositVout, "sequence": uint32(0xfffffffe)}}
	outputs := []map[string]any{{recipientAddr: json.Number("0.99998000")}}
	var unsignedPSBT string
	if err := e.Primary.Call("", "createpsbt", []any{inputs, outputs}, &unsignedPSBT); err != nil {
		return nil, fmt.Errorf("createpsbt: %w", err)
	}

	// Depositor signs ONLY its half (finalize=false -> 1-of-2 partial PSBT).
	var depSigned struct {
		PSBT     string `json:"psbt"`
		Complete bool   `json:"complete"`
	}
	if err := e.Primary.Call(depWallet, "walletprocesspsbt", []any{unsignedPSBT, true, "DEFAULT", true, false}, &depSigned); err != nil {
		return nil, fmt.Errorf("depositor walletprocesspsbt: %w", err)
	}
	if depSigned.Complete {
		return nil, errors.New("unexpected: 1-of-2 depositor signature alone marked 2-of-2 PSBT complete")
	}

	var decodedPSBT struct {
		Tx struct {
			TxID string `json:"txid"`
		} `json:"tx"`
		Inputs []struct {
			TaprootScripts []any             `json:"taproot_scripts"`
			TapScriptSigs  []json.RawMessage `json:"taproot_script_path_sigs"`
		} `json:"inputs"`
	}
	// Decode PSBT to inspect txid and Depositor's 64-byte Schnorr signature share.
	var rawPSBTMap map[string]any
	if err := e.Primary.Call("", "decodepsbt", []any{depSigned.PSBT}, &rawPSBTMap); err != nil {
		return nil, fmt.Errorf("decodepsbt: %w", err)
	}
	_ = decodedPSBT
	expectedTxID, depSigHex := extractPSBTTxIDAndFirstTapSig(rawPSBTMap)
	if depSigHex == "" {
		return nil, errors.New("depositor walletprocesspsbt did not attach a Tapscript signature")
	}

	partialBytes, err := base64.StdEncoding.DecodeString(depSigned.PSBT)
	if err != nil {
		return nil, err
	}

	return &LockedVault{
		VaultAddress:         vaultAddr,
		PublicDescriptor:     pubDesc,
		DepositTxID:          depositTxID,
		DepositVout:          depositVout,
		DepositBlock:         depHeight,
		DepositBlockHash:     depBlockHash,
		VaultScriptHex:       vaultScriptHex,
		RecipientAddress:     recipientAddr,
		DepositSats:          VaultDepositSats,
		WithdrawSats:         VaultWithdrawSats,
		FeeSats:              VaultFeeSats,
		ExpectedSweepTxID:    expectedTxID,
		DepositorSigHex:      depSigHex,
		DepositorPartialPSBT: partialBytes,
		DepositorWallet:      depWallet,
		ClaimerWallet:        clmWallet,
	}, nil
}

func extractPSBTTxIDAndFirstTapSig(m map[string]any) (txid, sigHex string) {
	if txObj, ok := m["tx"].(map[string]any); ok {
		if id, ok := txObj["txid"].(string); ok {
			txid = id
		}
	}
	inputs, _ := m["inputs"].([]any)
	if len(inputs) == 0 {
		return txid, ""
	}
	in0, _ := inputs[0].(map[string]any)
	// Bitcoin Core v28+/v30+ names Tapscript signatures "taproot_script_path_sigs"
	// (array of {pubkey, leaf_hash, sig}) or "tap_script_sigs".
	if arr, ok := in0["taproot_script_path_sigs"].([]any); ok && len(arr) > 0 {
		if entry, ok := arr[0].(map[string]any); ok {
			if s, ok := entry["sig"].(string); ok {
				return txid, s
			}
		}
	}
	if mp, ok := in0["tap_script_sigs"].(map[string]any); ok {
		for _, v := range mp {
			if s, ok := v.(string); ok {
				return txid, s
			}
		}
	}
	return txid, ""
}

// AttemptUnilateralSpend verifies on Bitcoin Core that actor ("depositor" or "claimer"),
// even with its private key LIVE and loaded in its wallet, cannot finalize a spend of
// the 2-of-2 Taproot vault alone.
func (e *Env) AttemptUnilateralSpend(vault *LockedVault, actor string) (UnilateralAttempt, error) {
	wallet := vault.DepositorWallet
	if actor == "claimer" {
		wallet = vault.ClaimerWallet
	}
	var dest string
	if err := e.Primary.Call(wallet, "getnewaddress", []any{"", "bech32m"}, &dest); err != nil {
		return UnilateralAttempt{}, err
	}
	inputs := []map[string]any{{"txid": vault.DepositTxID, "vout": vault.DepositVout, "sequence": uint32(0xfffffffe)}}
	outputs := []map[string]any{{dest: json.Number("0.99998000")}}
	var psbt string
	if err := e.Primary.Call("", "createpsbt", []any{inputs, outputs}, &psbt); err != nil {
		return UnilateralAttempt{}, err
	}
	var proc struct {
		PSBT     string `json:"psbt"`
		Complete bool   `json:"complete"`
	}
	if err := e.Primary.Call(wallet, "walletprocesspsbt", []any{psbt, true, "DEFAULT", true, true}, &proc); err != nil {
		return UnilateralAttempt{}, err
	}
	var fin struct {
		Complete bool `json:"complete"`
	}
	if err := e.Primary.Call("", "finalizepsbt", []any{proc.PSBT}, &fin); err != nil {
		return UnilateralAttempt{}, err
	}
	var rawMap map[string]any
	_ = e.Primary.Call("", "decodepsbt", []any{proc.PSBT}, &rawMap)
	_, sig := extractPSBTTxIDAndFirstTapSig(rawMap)

	return UnilateralAttempt{
		Actor:            actor,
		WalletKeysLive:   true,
		PartialSigned:    sig != "",
		FinalizableAlone: proc.Complete || fin.Complete,
	}, nil
}

func (e *Env) buildSignedCSVRefundTx(vault *LockedVault, refundDest string) (txHex, txid string, witnessItems int, err error) {
	inputs := []map[string]any{{"txid": vault.DepositTxID, "vout": vault.DepositVout, "sequence": VaultCSVBlocks}}
	outputs := []map[string]any{{refundDest: json.Number("0.99998000")}}
	var psbt string
	if err := e.Primary.Call("", "createpsbt", []any{inputs, outputs}, &psbt); err != nil {
		return "", "", 0, fmt.Errorf("createpsbt csv refund: %w", err)
	}
	var proc struct {
		PSBT     string `json:"psbt"`
		Complete bool   `json:"complete"`
		Hex      string `json:"hex"`
	}
	if err := e.Primary.Call(vault.DepositorWallet, "walletprocesspsbt", []any{psbt, true, "DEFAULT", true, true}, &proc); err != nil {
		return "", "", 0, fmt.Errorf("depositor csv walletprocesspsbt: %w", err)
	}
	txHex = proc.Hex
	if txHex == "" {
		var fin struct {
			Hex      string `json:"hex"`
			Complete bool   `json:"complete"`
		}
		if err := e.Primary.Call("", "finalizepsbt", []any{proc.PSBT}, &fin); err != nil {
			return "", "", 0, fmt.Errorf("finalizepsbt csv refund: %w", err)
		}
		if !fin.Complete || fin.Hex == "" {
			return "", "", 0, errors.New("csv refund PSBT failed to finalize with Depositor refund key")
		}
		txHex = fin.Hex
	}
	var decoded struct {
		TxID string `json:"txid"`
		Vin  []struct {
			TxInWitness []string `json:"txinwitness"`
		} `json:"vin"`
	}
	if err := e.Primary.Call("", "decoderawtransaction", []any{txHex}, &decoded); err != nil {
		return "", "", 0, err
	}
	if len(decoded.Vin) > 0 {
		witnessItems = len(decoded.Vin[0].TxInWitness)
	}
	return txHex, decoded.TxID, witnessItems, nil
}

// AttemptPrematureCSVRefund constructs and finalizes Depositor's Leaf-2 OP_CSV
// refund transaction (nSequence = VaultCSVBlocks) and submits it to Bitcoin Core's
// testmempoolaccept, demonstrating that consensus rejects early Depositor refunds
// with "non-BIP68-final" before VaultCSVBlocks confirmations have elapsed.
func (e *Env) AttemptPrematureCSVRefund(vault *LockedVault) (CSVRefundAttempt, error) {
	var refundAddr string
	if err := e.Primary.Call(vault.DepositorWallet, "getnewaddress", []any{"", "bech32m"}, &refundAddr); err != nil {
		return CSVRefundAttempt{}, err
	}
	txHex, txid, _, err := e.buildSignedCSVRefundTx(vault, refundAddr)
	if err != nil {
		return CSVRefundAttempt{}, err
	}
	var memRes []struct {
		TxID         string `json:"txid"`
		Allowed      bool   `json:"allowed"`
		RejectReason string `json:"reject-reason"`
	}
	if err := e.Primary.Call("", "testmempoolaccept", []any{[]string{txHex}}, &memRes); err != nil {
		return CSVRefundAttempt{}, fmt.Errorf("testmempoolaccept csv refund: %w", err)
	}
	if len(memRes) == 0 {
		return CSVRefundAttempt{}, errors.New("empty testmempoolaccept response")
	}
	return CSVRefundAttempt{
		CSVBlocks:        VaultCSVBlocks,
		LeafFinalized:    true,
		MempoolAllowed:   memRes[0].Allowed,
		RejectReason:     memRes[0].RejectReason,
		SignedRefundTxID: txid,
	}, nil
}

// ExecuteCSVRefund broadcasts and mines Depositor's Leaf-2 OP_CHECKSEQUENCEVERIFY
// refund transaction once at least VaultCSVBlocks confirmations have elapsed,
// recovering the locked funds when Claimer fails to burn on L2.
func (e *Env) ExecuteCSVRefund(vault *LockedVault) (*SweepSettlement, error) {
	if _, err := e.Primary.verifySignet(); err != nil {
		return nil, err
	}
	var refundAddr string
	if err := e.Primary.Call(vault.DepositorWallet, "getnewaddress", []any{"", "bech32m"}, &refundAddr); err != nil {
		return nil, err
	}
	txHex, _, witnessItems, err := e.buildSignedCSVRefundTx(vault, refundAddr)
	if err != nil {
		return nil, err
	}
	var refundTxID string
	if err := e.Primary.Call("", "sendrawtransaction", []any{txHex}, &refundTxID); err != nil {
		return nil, fmt.Errorf("sendrawtransaction csv refund: %w", err)
	}
	height, blockHash, err := e.MineBlocks(1)
	if err != nil {
		return nil, fmt.Errorf("mine csv refund block: %w", err)
	}
	unspent, err := e.IsOutPointUnspent(vault.DepositTxID, vault.DepositVout)
	if err != nil {
		return nil, err
	}
	var outInfo struct {
		Value float64 `json:"value"`
	}
	if err := e.Primary.Call("", "gettxout", []any{refundTxID, 0, true}, &outInfo); err != nil {
		return nil, fmt.Errorf("verify depositor refund utxo: %w", err)
	}
	peerSynced := false
	peerH := -1
	if e.Peer != nil {
		peerSynced = e.waitForPeerSync(5 * time.Second)
		_ = e.Peer.Call("", "getblockcount", nil, &peerH)
	}
	return &SweepSettlement{
		SweepTxID:       refundTxID,
		WitnessItems:    witnessItems,
		TxBytes:         len(txHex) / 2,
		BlockHeight:     height,
		BlockHash:       blockHash,
		PeerSynced:      peerSynced,
		PeerBlockHeight: peerH,
		VaultSpent:      !unspent,
		RecipientSats:   int64(outInfo.Value*1e8 + 0.5),
	}, nil
}

// IsOutPointUnspent reports whether txid:vout is currently unspent in the Signet UTXO set.
func (e *Env) IsOutPointUnspent(txid string, vout int) (bool, error) {
	var raw json.RawMessage
	if err := e.Primary.Call("", "gettxout", []any{txid, vout, true}, &raw); err != nil {
		return false, err
	}
	return len(raw) > 0 && string(raw) != "null", nil
}

// CoSignFinalizeOnly takes Depositor's Praxis-decrypted partial PSBT and co-signs +
// finalizes it with Claimer's wallet without broadcasting (useful when checking an
// alternate witness after the UTXO has already been swept).
func (e *Env) CoSignFinalizeOnly(vault *LockedVault, depositorPartialPSBT []byte) (txHex, txid string, witnessItems int, err error) {
	psbtB64 := base64.StdEncoding.EncodeToString(depositorPartialPSBT)
	var proc struct {
		PSBT     string `json:"psbt"`
		Complete bool   `json:"complete"`
		Hex      string `json:"hex"`
	}
	if err := e.Primary.Call(vault.ClaimerWallet, "walletprocesspsbt", []any{psbtB64, true, "DEFAULT", true, true}, &proc); err != nil {
		return "", "", 0, fmt.Errorf("claimer co-sign walletprocesspsbt: %w", err)
	}
	txHex = proc.Hex
	if txHex == "" {
		var fin struct {
			Hex      string `json:"hex"`
			Complete bool   `json:"complete"`
		}
		if err := e.Primary.Call("", "finalizepsbt", []any{proc.PSBT}, &fin); err != nil {
			return "", "", 0, fmt.Errorf("finalizepsbt: %w", err)
		}
		if !fin.Complete || fin.Hex == "" {
			return "", "", 0, errors.New("2-of-2 PSBT failed to finalize after Claimer co-sign")
		}
		txHex = fin.Hex
	}
	var decoded struct {
		TxID string `json:"txid"`
		Vin  []struct {
			TxInWitness []string `json:"txinwitness"`
		} `json:"vin"`
	}
	if err := e.Primary.Call("", "decoderawtransaction", []any{txHex}, &decoded); err != nil {
		return "", "", 0, err
	}
	if len(decoded.Vin) > 0 {
		witnessItems = len(decoded.Vin[0].TxInWitness)
	}
	return txHex, decoded.TxID, witnessItems, nil
}

// CoSignAndSweep takes Depositor's Praxis-decrypted 1-of-2 partial PSBT, co-signs the
// 2nd BIP-340 Schnorr signature using Claimer's wallet (with Depositor completely
// untouched/offline), finalizes the OP_CHECKSIGADD Tapscript witness, broadcasts on
// Signet, mines 1 block, and verifies UTXO settlement across peers.
func (e *Env) CoSignAndSweep(vault *LockedVault, depositorPartialPSBT []byte) (*SweepSettlement, error) {
	if _, err := e.Primary.verifySignet(); err != nil {
		return nil, err
	}
	txHex, _, witnessItems, err := e.CoSignFinalizeOnly(vault, depositorPartialPSBT)
	if err != nil {
		return nil, err
	}
	var sweepTxID string
	if err := e.Primary.Call("", "sendrawtransaction", []any{txHex}, &sweepTxID); err != nil {
		return nil, fmt.Errorf("sendrawtransaction: %w", err)
	}
	height, blockHash, err := e.MineBlocks(1)
	if err != nil {
		return nil, fmt.Errorf("mine settlement block: %w", err)
	}
	unspent, err := e.IsOutPointUnspent(vault.DepositTxID, vault.DepositVout)
	if err != nil {
		return nil, err
	}
	var outInfo struct {
		Value        float64 `json:"value"`
		ScriptPubKey struct {
			Address string `json:"address"`
		} `json:"scriptPubKey"`
	}
	if err := e.Primary.Call("", "gettxout", []any{sweepTxID, 0, true}, &outInfo); err != nil {
		return nil, fmt.Errorf("verify claimer utxo: %w", err)
	}
	recSats := int64(outInfo.Value*1e8 + 0.5)

	peerSynced := false
	peerH := -1
	if e.Peer != nil {
		peerSynced = e.waitForPeerSync(5 * time.Second)
		_ = e.Peer.Call("", "getblockcount", nil, &peerH)
	}
	return &SweepSettlement{
		SweepTxID:       sweepTxID,
		WitnessItems:    witnessItems,
		TxBytes:         len(txHex) / 2,
		BlockHeight:     height,
		BlockHash:       blockHash,
		PeerSynced:      peerSynced,
		PeerBlockHeight: peerH,
		VaultSpent:      !unspent,
		RecipientSats:   recSats,
	}, nil
}
