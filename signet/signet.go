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
	"encoding/binary"
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
	// VaultCSVBlocks is the default relative BIP-68 / OP_CHECKSEQUENCEVERIFY block
	// delay before Depositor can reclaim an unclaimed vault via Tapscript Leaf 2.
	VaultCSVBlocks uint32 = 6

	// TRUCTxVersion is the BIP-431 Topologically Restricted Until Confirmation
	// transaction version (nVersion = 3).
	TRUCTxVersion int = 3
	// P2AScriptPubKey is the BIP-431 / Bitcoin Core v28+ standard Pay-to-Anchor
	// witness v1 output script (OP_1 OP_PUSHBYTES_2 0x4e73).
	P2AScriptPubKey = "51024e73"
	// SignetP2AAddress is the Signet/Testnet Bech32m encoding of P2AScriptPubKey.
	SignetP2AAddress = "tb1pfees9rn5nz"
	// DefaultCPFPBumpSats is the default CPFP child fee bump for TRUC + P2A sweeps.
	DefaultCPFPBumpSats int64 = 15_000
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

// VaultConfig configures parameters for locking a 2-of-2 Taproot + CSV vault.
type VaultConfig struct {
	CSVBlocks        uint32 // Relative BIP-68 CSV block delay (0 defaults to VaultCSVBlocks = 6)
	EnableTRUCAnchor bool   // Build Leaf-1 PSBT as TRUC v3 with a 0-sat P2A anchor at vout 1
	DepositSats      int64  // Sats locked into the vault (0 defaults to VaultDepositSats)
	BaseFeeSats      int64  // Leaf-1 base fee in sats (0 stays 0 when EnableTRUCAnchor, else VaultFeeSats)
}

// MempoolAcceptResult summarizes one entry from Bitcoin Core's testmempoolaccept RPC.
type MempoolAcceptResult struct {
	TxID         string `json:"txid"`
	Allowed      bool   `json:"allowed"`
	RejectReason string `json:"reject-reason"`
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
	CSVBlocks            uint32 // Relative BIP-68 CSV timeout encoded in Leaf 2
	TRUCAnchorEnabled    bool   // True when Leaf-1 sweep is TRUC v3 with a P2A anchor output
	AnchorVout           int    // Output index of P2A anchor (1 when TRUCAnchorEnabled, -1 otherwise)
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

	// TRUC v3 + P2A CPFP package fields (populated by CoSignSweepWithCPFP).
	ChildTxID             string
	ChildConfirmed        bool
	ParentVSize           int
	ChildVSize            int
	PackageFeeSats        int64
	PackageFeeRateSatPerV float64
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

func normalizeVaultConfig(cfg VaultConfig) (VaultConfig, error) {
	if cfg.CSVBlocks == 0 {
		cfg.CSVBlocks = VaultCSVBlocks
	}
	if cfg.CSVBlocks > 0xffff {
		return VaultConfig{}, fmt.Errorf("CSVBlocks %d exceeds BIP-68 16-bit block limit (65535)", cfg.CSVBlocks)
	}
	if cfg.DepositSats < 0 {
		return VaultConfig{}, fmt.Errorf("DepositSats must be non-negative, got %d", cfg.DepositSats)
	}
	if cfg.DepositSats == 0 {
		cfg.DepositSats = VaultDepositSats
	}
	if cfg.BaseFeeSats < 0 {
		return VaultConfig{}, fmt.Errorf("BaseFeeSats must be non-negative, got %d", cfg.BaseFeeSats)
	}
	if !cfg.EnableTRUCAnchor && cfg.BaseFeeSats == 0 {
		cfg.BaseFeeSats = VaultFeeSats
	}
	if cfg.DepositSats-cfg.BaseFeeSats < 330 {
		return VaultConfig{}, fmt.Errorf("withdraw amount %d sats is below P2TR dust threshold (330 sats)", cfg.DepositSats-cfg.BaseFeeSats)
	}
	return cfg, nil
}

func formatBTC(sats int64) json.Number {
	sign := ""
	if sats < 0 {
		sign = "-"
		sats = -sats
	}
	return json.Number(fmt.Sprintf("%s%d.%08d", sign, sats/100_000_000, sats%100_000_000))
}

func csvBlocksForVault(vault *LockedVault) uint32 {
	if vault != nil && vault.CSVBlocks > 0 {
		return vault.CSVBlocks
	}
	return VaultCSVBlocks
}

func setRawTxVersion(rawHex string, version uint32) (string, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("decode raw tx hex: %w", err)
	}
	if len(raw) < 10 {
		return "", fmt.Errorf("raw tx too short (%d bytes)", len(raw))
	}
	binary.LittleEndian.PutUint32(raw[:4], version)
	return hex.EncodeToString(raw), nil
}

func (e *Env) createRawTxWithVersion(inputs, outputs []map[string]any, locktime uint32, replaceable bool, version int) (string, error) {
	var rawHex string
	if err := e.Primary.Call("", "createrawtransaction", []any{inputs, outputs, locktime, replaceable, version}, &rawHex); err == nil {
		return rawHex, nil
	}
	if err := e.Primary.Call("", "createrawtransaction", []any{inputs, outputs, locktime, replaceable}, &rawHex); err != nil {
		return "", fmt.Errorf("createrawtransaction: %w", err)
	}
	if version != 2 {
		return setRawTxVersion(rawHex, uint32(version))
	}
	return rawHex, nil
}

func (e *Env) createPSBTWithVersion(inputs, outputs []map[string]any, locktime uint32, replaceable bool, version int) (string, error) {
	var psbt string
	if version == 2 && locktime == 0 {
		if err := e.Primary.Call("", "createpsbt", []any{inputs, outputs}, &psbt); err != nil {
			return "", fmt.Errorf("createpsbt: %w", err)
		}
		return psbt, nil
	}
	if err := e.Primary.Call("", "createpsbt", []any{inputs, outputs, locktime, replaceable, version}, &psbt); err == nil {
		return psbt, nil
	}
	rawHex, err := e.createRawTxWithVersion(inputs, outputs, locktime, replaceable, version)
	if err != nil {
		return "", err
	}
	if err := e.Primary.Call("", "converttopsbt", []any{rawHex, false, false}, &psbt); err != nil {
		return "", fmt.Errorf("converttopsbt: %w", err)
	}
	return psbt, nil
}

// TestMempoolAccept tests whether one or more raw hex transactions would be accepted by mempool.
func (e *Env) TestMempoolAccept(rawTxHexes ...string) ([]MempoolAcceptResult, error) {
	var res []MempoolAcceptResult
	if err := e.Primary.Call("", "testmempoolaccept", []any{rawTxHexes}, &res); err != nil {
		return nil, fmt.Errorf("testmempoolaccept: %w", err)
	}
	return res, nil
}

// LockTaprootVault creates an operator-free 2-of-2 Tapscript vault on Signet
// using the default configuration (1.0 sBTC, 6-block CSV, legacy v2 2,000-sat fee sweep):
//  1. Creates TWO independent live wallets: Depositor and Claimer (both retain
//     their private keys—nobody is trusted to delete a key).
//  2. Derives tr(NUMS, {multi_a(2, Depositor, Claimer), and_v(v:pk(Depositor_refund), older(6))})
//     so key-path spends are impossible and Leaf 1 requires BOTH Schnorr sigs.
//  3. Funds the 2-of-2 P2TR vault with 1.00000000 sBTC and mines 1 Signet block.
//  4. Depositor signs ONLY its 1-of-2 partial PSBT paying Claimer 0.99998000 sBTC,
//     returning the raw partial PSBT bytes to encrypt inside Praxis.
func (e *Env) LockTaprootVault() (*LockedVault, error) {
	return e.LockTaprootVaultWithConfig(VaultConfig{
		CSVBlocks:        VaultCSVBlocks,
		EnableTRUCAnchor: false,
		DepositSats:      VaultDepositSats,
		BaseFeeSats:      VaultFeeSats,
	})
}

// LockTaprootVaultWithConfig locks a configurable two-leaf Taproot vault on Signet:
//   - Custom BIP-68 CSV timeout via cfg.CSVBlocks (default 6).
//   - Optional BIP-431 TRUC v3 + 0-sat Pay-to-Anchor (P2A, script 51024e73) Leaf-1
//     sweep via cfg.EnableTRUCAnchor so Claimer can dynamically fee-bump via CPFP
//     without altering Depositor's pre-signed Tapscript signature.
func (e *Env) LockTaprootVaultWithConfig(cfg VaultConfig) (*LockedVault, error) {
	if _, err := e.Primary.verifySignet(); err != nil {
		return nil, err
	}
	cfg, err := normalizeVaultConfig(cfg)
	if err != nil {
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
		BIP341NUMSInternalKey, dep0Priv, clm0Pub, dep1Priv, cfg.CSVBlocks)
	rawForClm := fmt.Sprintf("tr(%s,{multi_a(2,%s,%s),and_v(v:pk(%s),older(%d))})",
		BIP341NUMSInternalKey, dep0Pub, clm0Priv, dep1Pub, cfg.CSVBlocks)
	rawPub := fmt.Sprintf("tr(%s,{multi_a(2,%s,%s),and_v(v:pk(%s),older(%d))})",
		BIP341NUMSInternalKey, dep0Pub, clm0Pub, dep1Pub, cfg.CSVBlocks)

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

	// Fund the 2-of-2 Taproot vault with cfg.DepositSats and confirm in 1 Signet block.
	var depositTxID string
	if err := e.Primary.Call("miner", "sendtoaddress", []any{vaultAddr, formatBTC(cfg.DepositSats)}, &depositTxID); err != nil {
		return nil, fmt.Errorf("fund 2-of-2 vault: %w", err)
	}
	// When TRUC+P2A is enabled, seed Claimer's wallet with a confirmed fee UTXO in the
	// same deposit block so CoSignSweepWithCPFP satisfies BIP-431's 1P1C topology
	// immediately without advancing the chain before sweep submission.
	if cfg.EnableTRUCAnchor {
		var feeAddr string
		if err := e.Primary.Call(clmWallet, "getnewaddress", []any{"", "bech32m"}, &feeAddr); err != nil {
			return nil, fmt.Errorf("claimer cpfp fee address: %w", err)
		}
		var feeFundTxID string
		if err := e.Primary.Call("miner", "sendtoaddress", []any{feeAddr, formatBTC(1_000_000)}, &feeFundTxID); err != nil {
			return nil, fmt.Errorf("fund claimer cpfp fee reserve: %w", err)
		}
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

	// Construct the unsigned Leaf-1 withdrawal PSBT.
	// Setting sequence=0xfffffffe disables BIP-68 relative locktime so Miniscript
	// targets Leaf 1 (multi_a(2, Depositor, Claimer)) rather than Leaf 2 (older(N)).
	withdrawSats := cfg.DepositSats - cfg.BaseFeeSats
	inputs := []map[string]any{{"txid": depositTxID, "vout": depositVout, "sequence": uint32(0xfffffffe)}}
	outputs := []map[string]any{{recipientAddr: formatBTC(withdrawSats)}}
	txVersion := 2
	anchorVout := -1
	if cfg.EnableTRUCAnchor {
		txVersion = TRUCTxVersion
		anchorVout = 1
		outputs = append(outputs, map[string]any{SignetP2AAddress: formatBTC(0)})
	}
	unsignedPSBT, err := e.createPSBTWithVersion(inputs, outputs, 0, false, txVersion)
	if err != nil {
		return nil, err
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

	// Decode PSBT to inspect txid, TRUC/P2A invariants, and Depositor's 64-byte Schnorr share.
	var rawPSBTMap map[string]any
	if err := e.Primary.Call("", "decodepsbt", []any{depSigned.PSBT}, &rawPSBTMap); err != nil {
		return nil, fmt.Errorf("decodepsbt: %w", err)
	}
	expectedTxID, depSigHex := extractPSBTTxIDAndFirstTapSig(rawPSBTMap)
	if depSigHex == "" {
		return nil, errors.New("depositor walletprocesspsbt did not attach a Tapscript signature")
	}
	if cfg.EnableTRUCAnchor {
		var decodedPSBT struct {
			Tx struct {
				Version int `json:"version"`
				Vout    []struct {
					Value        float64 `json:"value"`
					N            int     `json:"n"`
					ScriptPubKey struct {
						Hex  string `json:"hex"`
						Type string `json:"type"`
					} `json:"scriptPubKey"`
				} `json:"vout"`
			} `json:"tx"`
		}
		if err := e.Primary.Call("", "decodepsbt", []any{depSigned.PSBT}, &decodedPSBT); err != nil {
			return nil, fmt.Errorf("decodepsbt verify truc: %w", err)
		}
		if decodedPSBT.Tx.Version != TRUCTxVersion {
			return nil, fmt.Errorf("expected TRUC v%d partial PSBT, got version %d", TRUCTxVersion, decodedPSBT.Tx.Version)
		}
		if len(decodedPSBT.Tx.Vout) != 2 {
			return nil, fmt.Errorf("expected 2 outputs on TRUC+P2A sweep PSBT, got %d", len(decodedPSBT.Tx.Vout))
		}
		anchorOut := decodedPSBT.Tx.Vout[anchorVout]
		if anchorOut.ScriptPubKey.Hex != P2AScriptPubKey {
			return nil, fmt.Errorf("expected P2A scriptPubKey %s at vout %d, got %s", P2AScriptPubKey, anchorVout, anchorOut.ScriptPubKey.Hex)
		}
		if int64(anchorOut.Value*1e8+0.5) != 0 {
			return nil, fmt.Errorf("expected 0-sat P2A anchor at vout %d, got %.8f", anchorVout, anchorOut.Value)
		}
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
		DepositSats:          cfg.DepositSats,
		WithdrawSats:         withdrawSats,
		FeeSats:              cfg.BaseFeeSats,
		CSVBlocks:            cfg.CSVBlocks,
		TRUCAnchorEnabled:    cfg.EnableTRUCAnchor,
		AnchorVout:           anchorVout,
		ExpectedSweepTxID:    expectedTxID,
		DepositorSigHex:      depSigHex,
		DepositorPartialPSBT: partialBytes,
		DepositorWallet:      depWallet,
		ClaimerWallet:        clmWallet,
	}, nil
}

func bip341TapLeafHash(leafVer byte, script []byte) [32]byte {
	tag := sha256.Sum256([]byte("TapLeaf"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write([]byte{leafVer})
	n := len(script)
	switch {
	case n < 0xfd:
		h.Write([]byte{byte(n)})
	case n <= 0xffff:
		var buf [3]byte
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(n))
		h.Write(buf[:])
	default:
		var buf [5]byte
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(n))
		h.Write(buf[:])
	}
	h.Write(script)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func reverseHexBytes(b []byte) string {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(rev)
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

	// Identify the multi_a(2) Leaf-1 TapLeaf hash so we always return Depositor's
	// Leaf-1 claim signature even when walletprocesspsbt also signs Leaf 2 (older(N))
	// and PSBT map ordering places Leaf 2's pubkey first.
	leaf1Hashes := map[string]bool{}
	if scripts, ok := in0["taproot_scripts"].([]any); ok {
		for _, item := range scripts {
			scObj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			scHex, _ := scObj["script"].(string)
			// multi_a(2): <pk1> OP_CHECKSIG(ac) <pk2> OP_CHECKSIGADD(ba) OP_2(52) OP_NUMEQUAL(9c).
			if !strings.HasSuffix(strings.ToLower(scHex), "ba529c") {
				continue
			}
			scBytes, err := hex.DecodeString(scHex)
			if err != nil {
				continue
			}
			leafVer := byte(0xc0)
			if lv, ok := scObj["leaf_ver"].(float64); ok {
				leafVer = byte(lv)
			}
			lh := bip341TapLeafHash(leafVer, scBytes)
			leaf1Hashes[hex.EncodeToString(lh[:])] = true
			leaf1Hashes[reverseHexBytes(lh[:])] = true
		}
	}

	// Bitcoin Core v28+/v30+ names Tapscript signatures "taproot_script_path_sigs"
	// (array of {pubkey, leaf_hash, sig}) or "tap_script_sigs".
	if arr, ok := in0["taproot_script_path_sigs"].([]any); ok && len(arr) > 0 {
		if len(leaf1Hashes) > 0 {
			for _, item := range arr {
				entry, ok := item.(map[string]any)
				if !ok {
					continue
				}
				lh, _ := entry["leaf_hash"].(string)
				s, _ := entry["sig"].(string)
				if s != "" && leaf1Hashes[strings.ToLower(lh)] {
					return txid, s
				}
			}
		}
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
	depositSats := vault.DepositSats
	if depositSats <= 0 {
		depositSats = VaultDepositSats
	}
	feeSats := vault.FeeSats
	if feeSats <= 0 {
		feeSats = VaultFeeSats
	}
	inputs := []map[string]any{{"txid": vault.DepositTxID, "vout": vault.DepositVout, "sequence": uint32(0xfffffffe)}}
	outputs := []map[string]any{{dest: formatBTC(depositSats - feeSats)}}
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
	csvBlocks := csvBlocksForVault(vault)
	depositSats := vault.DepositSats
	if depositSats <= 0 {
		depositSats = VaultDepositSats
	}
	refundFee := vault.FeeSats
	if refundFee <= 0 {
		refundFee = VaultFeeSats
	}
	if depositSats-refundFee < 330 {
		return "", "", 0, fmt.Errorf("vault deposit %d sats too small for refund fee %d sats", depositSats, refundFee)
	}
	inputs := []map[string]any{{"txid": vault.DepositTxID, "vout": vault.DepositVout, "sequence": csvBlocks}}
	outputs := []map[string]any{{refundDest: formatBTC(depositSats - refundFee)}}
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
// refund transaction (nSequence = vault.CSVBlocks) and submits it to Bitcoin Core's
// testmempoolaccept, demonstrating that consensus rejects early Depositor refunds
// with "non-BIP68-final" before vault.CSVBlocks confirmations have elapsed.
func (e *Env) AttemptPrematureCSVRefund(vault *LockedVault) (CSVRefundAttempt, error) {
	csvBlocks := csvBlocksForVault(vault)
	var refundAddr string
	if err := e.Primary.Call(vault.DepositorWallet, "getnewaddress", []any{"", "bech32m"}, &refundAddr); err != nil {
		return CSVRefundAttempt{}, err
	}
	txHex, txid, _, err := e.buildSignedCSVRefundTx(vault, refundAddr)
	if err != nil {
		return CSVRefundAttempt{}, err
	}
	memRes, err := e.TestMempoolAccept(txHex)
	if err != nil {
		return CSVRefundAttempt{}, fmt.Errorf("testmempoolaccept csv refund: %w", err)
	}
	if len(memRes) == 0 {
		return CSVRefundAttempt{}, errors.New("empty testmempoolaccept response")
	}
	return CSVRefundAttempt{
		CSVBlocks:        csvBlocks,
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

type confirmedUTXO struct {
	TxID         string
	Vout         int
	AmountSats   int64
	ScriptPubKey string
}

func (e *Env) ensureConfirmedFeeUTXO(wallet, excludeTxID string, excludeVout int, minSats int64) (confirmedUTXO, error) {
	find := func() (confirmedUTXO, bool, error) {
		var utxos []struct {
			TxID         string  `json:"txid"`
			Vout         int     `json:"vout"`
			Amount       float64 `json:"amount"`
			ScriptPubKey string  `json:"scriptPubKey"`
			Spendable    bool    `json:"spendable"`
		}
		if err := e.Primary.Call(wallet, "listunspent", []any{1, 9_999_999}, &utxos); err != nil {
			return confirmedUTXO{}, false, fmt.Errorf("listunspent %s: %w", wallet, err)
		}
		for _, u := range utxos {
			if !u.Spendable {
				continue
			}
			if u.TxID == excludeTxID && u.Vout == excludeVout {
				continue
			}
			sats := int64(u.Amount*1e8 + 0.5)
			if sats >= minSats {
				return confirmedUTXO{
					TxID:         u.TxID,
					Vout:         u.Vout,
					AmountSats:   sats,
					ScriptPubKey: u.ScriptPubKey,
				}, true, nil
			}
		}
		return confirmedUTXO{}, false, nil
	}

	if u, ok, err := find(); err != nil {
		return confirmedUTXO{}, err
	} else if ok {
		return u, nil
	}

	// Top up Claimer wallet with a confirmed UTXO from miner so the CPFP child
	// has only ONE unconfirmed parent (strict BIP-431 TRUC 1P1C topology).
	var feeAddr string
	if err := e.Primary.Call(wallet, "getnewaddress", []any{"", "bech32m"}, &feeAddr); err != nil {
		return confirmedUTXO{}, fmt.Errorf("claimer fee top-up address: %w", err)
	}
	fundSats := minSats + 1_000_000
	var txid string
	if err := e.Primary.Call("miner", "sendtoaddress", []any{feeAddr, formatBTC(fundSats)}, &txid); err != nil {
		return confirmedUTXO{}, fmt.Errorf("fund claimer fee top-up: %w", err)
	}
	if _, _, err := e.MineBlocks(1); err != nil {
		return confirmedUTXO{}, fmt.Errorf("confirm claimer fee top-up: %w", err)
	}
	u, ok, err := find()
	if err != nil {
		return confirmedUTXO{}, err
	}
	if !ok {
		return confirmedUTXO{}, fmt.Errorf("no confirmed spendable UTXO >= %d sats in wallet %s after funding", minSats, wallet)
	}
	return u, nil
}

// CoSignSweepWithCPFP co-signs and finalizes Depositor's pre-signed TRUC v3 Leaf-1
// sweep PSBT (preserving Depositor's Schnorr signature untouched), constructs and
// signs a TRUC v3 CPFP child spending the parent's P2A anchor (vout 1, empty witness [])
// plus a confirmed Claimer fee UTXO paying bumpFeeSats, submits [parent, child]
// atomically via submitpackage, mines 1 block, and verifies BOTH transactions
// confirmed on Signet with full payout to Claimer.
func (e *Env) CoSignSweepWithCPFP(vault *LockedVault, depositorPartialPSBT []byte, bumpFeeSats int64) (*SweepSettlement, error) {
	if _, err := e.Primary.verifySignet(); err != nil {
		return nil, err
	}
	if vault == nil {
		return nil, errors.New("vault is nil")
	}
	if !vault.TRUCAnchorEnabled || vault.AnchorVout < 0 {
		return nil, errors.New("vault was not locked with EnableTRUCAnchor=true")
	}
	if bumpFeeSats <= 0 {
		return nil, fmt.Errorf("bumpFeeSats must be positive, got %d", bumpFeeSats)
	}

	// 1. Co-sign & finalize the pre-signed v3 TRUC parent WITHOUT altering Depositor's sig.
	parentHex, parentTxID, witnessItems, err := e.CoSignFinalizeOnly(vault, depositorPartialPSBT)
	if err != nil {
		return nil, err
	}
	if vault.ExpectedSweepTxID != "" && parentTxID != vault.ExpectedSweepTxID {
		return nil, fmt.Errorf("finalized TRUC parent txid %s != expected %s", parentTxID, vault.ExpectedSweepTxID)
	}

	var parentDec struct {
		TxID    string `json:"txid"`
		Hash    string `json:"hash"`
		Version int    `json:"version"`
		VSize   int    `json:"vsize"`
		Vin     []struct {
			TxInWitness []string `json:"txinwitness"`
		} `json:"vin"`
		Vout []struct {
			Value        float64 `json:"value"`
			N            int     `json:"n"`
			ScriptPubKey struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if err := e.Primary.Call("", "decoderawtransaction", []any{parentHex}, &parentDec); err != nil {
		return nil, fmt.Errorf("decode TRUC parent tx: %w", err)
	}
	if parentDec.Version != TRUCTxVersion {
		return nil, fmt.Errorf("expected TRUC parent version %d, got %d", TRUCTxVersion, parentDec.Version)
	}
	if vault.AnchorVout >= len(parentDec.Vout) {
		return nil, fmt.Errorf("anchor vout %d out of range (parent has %d outputs)", vault.AnchorVout, len(parentDec.Vout))
	}
	anchorOut := parentDec.Vout[vault.AnchorVout]
	if anchorOut.ScriptPubKey.Hex != P2AScriptPubKey {
		return nil, fmt.Errorf("parent vout %d scriptPubKey %s != P2A %s", vault.AnchorVout, anchorOut.ScriptPubKey.Hex, P2AScriptPubKey)
	}
	if vault.DepositorSigHex != "" {
		foundDepSig := false
		if len(parentDec.Vin) > 0 {
			for _, item := range parentDec.Vin[0].TxInWitness {
				if strings.EqualFold(item, vault.DepositorSigHex) {
					foundDepSig = true
					break
				}
			}
		}
		if !foundDepSig {
			return nil, errors.New("depositor pre-signed Schnorr signature missing from finalized parent witness")
		}
	}
	anchorSats := int64(anchorOut.Value*1e8 + 0.5)

	// 2. Obtain a confirmed Claimer fee UTXO (strict BIP-431 1P1C: child has only 1 unconfirmed parent).
	feeUTXO, err := e.ensureConfirmedFeeUTXO(vault.ClaimerWallet, vault.DepositTxID, vault.DepositVout, bumpFeeSats+1_000)
	if err != nil {
		return nil, err
	}
	changeSats := feeUTXO.AmountSats + anchorSats - bumpFeeSats
	if changeSats < 330 {
		return nil, fmt.Errorf("cpfp child change %d sats below P2TR dust threshold", changeSats)
	}

	var changeAddr string
	if err := e.Primary.Call(vault.ClaimerWallet, "getnewaddress", []any{"", "bech32m"}, &changeAddr); err != nil {
		return nil, fmt.Errorf("claimer cpfp change address: %w", err)
	}

	// 3. Construct and sign the v3 TRUC CPFP child spending parent:anchorVout + Claimer fee UTXO.
	childInputs := []map[string]any{
		{"txid": parentTxID, "vout": vault.AnchorVout, "sequence": uint32(0xfffffffd)},
		{"txid": feeUTXO.TxID, "vout": feeUTXO.Vout, "sequence": uint32(0xfffffffd)},
	}
	childOutputs := []map[string]any{
		{changeAddr: formatBTC(changeSats)},
	}
	unsignedChildHex, err := e.createRawTxWithVersion(childInputs, childOutputs, 0, true, TRUCTxVersion)
	if err != nil {
		return nil, fmt.Errorf("create cpfp child raw tx: %w", err)
	}

	prevTxs := []map[string]any{{
		"txid":         parentTxID,
		"vout":         vault.AnchorVout,
		"scriptPubKey": P2AScriptPubKey,
		"amount":       formatBTC(anchorSats),
	}}
	var signedChild struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
		Errors   []struct {
			TxID  string `json:"txid"`
			Vout  int    `json:"vout"`
			Error string `json:"error"`
		} `json:"errors"`
	}
	if err := e.Primary.Call(vault.ClaimerWallet, "signrawtransactionwithwallet", []any{unsignedChildHex, prevTxs, "DEFAULT"}, &signedChild); err != nil {
		return nil, fmt.Errorf("sign cpfp child tx: %w", err)
	}
	if !signedChild.Complete || signedChild.Hex == "" {
		msg := "incomplete signature"
		if len(signedChild.Errors) > 0 {
			msg = signedChild.Errors[0].Error
		}
		return nil, fmt.Errorf("cpfp child tx signing failed: %s", msg)
	}

	var childDec struct {
		TxID    string `json:"txid"`
		Hash    string `json:"hash"`
		Version int    `json:"version"`
		VSize   int    `json:"vsize"`
		Vin     []struct {
			TxID        string   `json:"txid"`
			Vout        int      `json:"vout"`
			TxInWitness []string `json:"txinwitness"`
		} `json:"vin"`
	}
	if err := e.Primary.Call("", "decoderawtransaction", []any{signedChild.Hex}, &childDec); err != nil {
		return nil, fmt.Errorf("decode cpfp child tx: %w", err)
	}
	if childDec.Version != TRUCTxVersion {
		return nil, fmt.Errorf("expected TRUC child version %d, got %d", TRUCTxVersion, childDec.Version)
	}
	if len(childDec.Vin) != 2 || childDec.Vin[0].TxID != parentTxID || childDec.Vin[0].Vout != vault.AnchorVout {
		return nil, errors.New("cpfp child vin[0] does not reference parent P2A anchor outpoint")
	}
	if len(childDec.Vin[0].TxInWitness) != 0 {
		return nil, fmt.Errorf("expected empty witness [] on P2A anchor spend, got %d items", len(childDec.Vin[0].TxInWitness))
	}

	// 4. Submit [parentHex, childHex] atomically via submitpackage.
	var pkgRes struct {
		PackageMsg string `json:"package_msg"`
		TxResults  map[string]struct {
			TxID  string `json:"txid"`
			VSize int    `json:"vsize"`
			Fees  *struct {
				Base              float64  `json:"base"`
				EffectiveFeeRate  float64  `json:"effective-feerate"`
				EffectiveIncludes []string `json:"effective-includes"`
			} `json:"fees"`
			Error string `json:"error"`
		} `json:"tx-results"`
	}
	if err := e.Primary.Call("", "submitpackage", []any{[]string{parentHex, signedChild.Hex}}, &pkgRes); err != nil {
		return nil, fmt.Errorf("submitpackage: %w", err)
	}
	if pkgRes.PackageMsg != "success" {
		var details []string
		for wtxid, r := range pkgRes.TxResults {
			if r.Error != "" {
				shortID := wtxid
				if len(shortID) > 12 {
					shortID = shortID[:12]
				}
				details = append(details, fmt.Sprintf("%s: %s", shortID, r.Error))
			}
		}
		return nil, fmt.Errorf("submitpackage failed (%s): %s", pkgRes.PackageMsg, strings.Join(details, "; "))
	}

	var effFeeRateSatPerV float64
	for _, r := range pkgRes.TxResults {
		if r.Error != "" {
			return nil, fmt.Errorf("submitpackage tx %s error: %s", r.TxID, r.Error)
		}
		if r.TxID == parentTxID && r.VSize > 0 {
			parentDec.VSize = r.VSize
		}
		if r.TxID == childDec.TxID && r.VSize > 0 {
			childDec.VSize = r.VSize
		}
		if r.Fees != nil && r.Fees.EffectiveFeeRate > 0 {
			// Bitcoin Core reports effective-feerate in BTC/kvB; 1 BTC/kvB = 1e5 sat/vB.
			effFeeRateSatPerV = r.Fees.EffectiveFeeRate * 1e5
		}
	}
	packageFeeSats := vault.FeeSats + bumpFeeSats
	totalVSize := parentDec.VSize + childDec.VSize
	if effFeeRateSatPerV == 0 && totalVSize > 0 {
		effFeeRateSatPerV = float64(packageFeeSats) / float64(totalVSize)
	}

	// 5. Mine 1 Signet block and verify BOTH parent and child confirmed in that block.
	height, blockHash, err := e.MineBlocks(1)
	if err != nil {
		return nil, fmt.Errorf("mine cpfp package block: %w", err)
	}
	var blk struct {
		Tx []string `json:"tx"`
	}
	if err := e.Primary.Call("", "getblock", []any{blockHash, 1}, &blk); err != nil {
		return nil, fmt.Errorf("getblock %s: %w", blockHash, err)
	}
	var parentInBlock, childInBlock bool
	for _, txid := range blk.Tx {
		if txid == parentTxID {
			parentInBlock = true
		}
		if txid == childDec.TxID {
			childInBlock = true
		}
	}
	if !parentInBlock || !childInBlock {
		return nil, fmt.Errorf("expected both parent (%s, inBlock=%v) and child (%s, inBlock=%v) in block %s",
			parentTxID, parentInBlock, childDec.TxID, childInBlock, blockHash)
	}

	vaultUnspent, err := e.IsOutPointUnspent(vault.DepositTxID, vault.DepositVout)
	if err != nil {
		return nil, err
	}
	anchorUnspent, err := e.IsOutPointUnspent(parentTxID, vault.AnchorVout)
	if err != nil {
		return nil, err
	}
	if anchorUnspent {
		return nil, fmt.Errorf("P2A anchor %s:%d unexpectedly remained unspent after CPFP confirmation", parentTxID, vault.AnchorVout)
	}

	var outInfo struct {
		Value float64 `json:"value"`
	}
	if err := e.Primary.Call("", "gettxout", []any{parentTxID, 0, true}, &outInfo); err != nil {
		return nil, fmt.Errorf("verify claimer payout utxo: %w", err)
	}
	recSats := int64(outInfo.Value*1e8 + 0.5)

	peerSynced := false
	peerH := -1
	if e.Peer != nil {
		peerSynced = e.waitForPeerSync(5 * time.Second)
		_ = e.Peer.Call("", "getblockcount", nil, &peerH)
	}

	return &SweepSettlement{
		SweepTxID:             parentTxID,
		WitnessItems:          witnessItems,
		TxBytes:               len(parentHex) / 2,
		BlockHeight:           height,
		BlockHash:             blockHash,
		PeerSynced:            peerSynced,
		PeerBlockHeight:       peerH,
		VaultSpent:            !vaultUnspent,
		RecipientSats:         recSats,
		ChildTxID:             childDec.TxID,
		ChildConfirmed:        childInBlock,
		ParentVSize:           parentDec.VSize,
		ChildVSize:            childDec.VSize,
		PackageFeeSats:        packageFeeSats,
		PackageFeeRateSatPerV: effFeeRateSatPerV,
	}, nil
}
