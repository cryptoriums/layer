package app

import (
	"context"
	"fmt"

	"github.com/spf13/viper"
	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
)

// voteExtRequestID tags signer RPCs for attribution in the remote signer's logs.
const voteExtRequestID = "layer-vote-ext"

// InitialRegistrationMessages returns the two messages an operator signs to
// register its EVM address. The remote signer derives the identical pair from
// the operator address, so both signing paths cover the same bytes.
func InitialRegistrationMessages(operatorAddress string) (msgA, msgB string) {
	msgA = fmt.Sprintf("TellorLayer: Initial bridge signature A for operator %s", operatorAddress)
	msgB = fmt.Sprintf("TellorLayer: Initial bridge signature B for operator %s", operatorAddress)
	return msgA, msgB
}

// VoteExtensionSigner is the interface VoteExtHandler uses for all bridge signing.
// Implemented by KeyringSigner or GRPCRemoteSigner.
type VoteExtensionSigner interface {
	// SignCheckpoint signs a valset checkpoint and returns a 64-byte secp256k1 signature.
	SignCheckpoint(ctx context.Context, req *signerv1.SignBridgeCheckpointRequest) ([]byte, error)

	// SignOracleAttestation signs an oracle-attestation snapshot and returns a 64-byte secp256k1 signature.
	SignOracleAttestation(ctx context.Context, req *signerv1.SignOracleAttestationRequest) ([]byte, error)

	// SignInitialRegistration signs the operator's two initial bridge-registration
	// messages and returns signatures A and B.
	SignInitialRegistration(ctx context.Context, operatorAddress string) (sigA, sigB []byte, err error)

	// GetOperatorAddress returns the bech32 validator operator address.
	GetOperatorAddress(ctx context.Context) (string, error)
}

func RemoteVoteExtensionSigner() (VoteExtensionSigner, error) {
	addr := viper.GetString("remote-signer-addr")
	if addr == "" {
		return nil, nil
	}
	return NewGRPCRemoteSigner(GRPCSignerConfig{
		Address:    addr,
		Insecure:   viper.GetBool("remote-signer-insecure"),
		CACert:     viper.GetString("remote-signer-ca-cert"),
		ClientCert: viper.GetString("remote-signer-client-cert"),
		ClientKey:  viper.GetString("remote-signer-client-key"),
		ServerName: viper.GetString("remote-signer-server-name"),
	})
}
