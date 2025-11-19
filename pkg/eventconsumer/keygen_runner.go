package eventconsumer

import (
	"context"
	"fmt"

	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/taurus"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

func (ec *eventConsumer) runECDSAKeygen(
	ctx context.Context,
	walletID string,
	algo types.Protocol,
	natMsg *nats.Msg,
) ([]byte, error) {
	switch algo {
	case types.ProtocolCGGMP21:
		ts, err := ec.node.CreateTaurusSession(
			walletID,
			ec.mpcThreshold,
			types.ProtocolCGGMP21,
			taurus.ActKeygen,
		)
		if err != nil {
			return nil, err
		}
		res, err := ts.Keygen(ctx)
		if err != nil {
			return nil, err
		}
		return res.PubKeyBytes, nil

	case types.ProtocolFROST:
		ts, err := ec.node.CreateTaurusSession(
			walletID,
			ec.mpcThreshold,
			types.ProtocolFROST,
			taurus.ActKeygen,
		)
		if err != nil {
			return nil, err
		}
		res, err := ts.Keygen(ctx)
		if err != nil {
			return nil, err
		}
		return res.PubKeyBytes, nil

	case types.ProtocolTaproot:
		ts, err := ec.node.CreateTaurusSession(
			walletID,
			ec.mpcThreshold,
			types.ProtocolTaproot,
			taurus.ActKeygen,
		)
		if err != nil {
			return nil, err
		}
		res, err := ts.Keygen(ctx)
		if err != nil {
			return nil, err
		}
		return res.PubKeyBytes, nil
	case types.ProtocolGG18:
		fallthrough
	default:
		// Fallback to GG18 ECDSA when algorithm is GG18 or unspecified/unknown
		sess, err := ec.node.CreateKeyGenSession(
			mpc.SessionTypeECDSA,
			walletID,
			ec.mpcThreshold,
			ec.genKeyResultQueue,
		)
		if err != nil {
			ec.handleKeygenSessionError(
				walletID,
				err,
				"Failed to create ECDSA (GG18) session",
				natMsg,
			)
			return nil, err
		}
		sess.Init()
		sess.ListenToIncomingMessageAsync()
		ec.warmUpSession()

		ctxLocal, cancel := context.WithCancel(ctx)
		defer cancel()
		go sess.GenerateKey(cancel)

		select {
		case err := <-sess.ErrChan():
			if err != nil {
				return nil, err
			}
		case <-ctxLocal.Done():
			// success
		case <-ctx.Done():
			return nil, fmt.Errorf("ECDSA keygen cancelled")
		}
		return sess.GetPubKeyResult(), nil
	}
}

func (ec *eventConsumer) runEdDSAKeygen(
	ctx context.Context,
	walletID string,
	algo types.Protocol,
	natMsg *nats.Msg,
) ([]byte, error) {
	switch algo {
	case types.ProtocolGG18:
		fallthrough
	default:
		sess, err := ec.node.CreateKeyGenSession(
			mpc.SessionTypeEDDSA,
			walletID,
			ec.mpcThreshold,
			ec.genKeyResultQueue,
		)
		if err != nil {
			ec.handleKeygenSessionError(
				walletID,
				err,
				"Failed to create EdDSA keygen session",
				natMsg,
			)
			return nil, err
		}
		sess.Init()
		sess.ListenToIncomingMessageAsync()
		ec.warmUpSession()

		ctxLocal, cancel := context.WithCancel(ctx)
		defer cancel()
		go sess.GenerateKey(cancel)

		select {
		case err := <-sess.ErrChan():
			if err != nil {
				return nil, err
			}
		case <-ctxLocal.Done():
			// success
		case <-ctx.Done():
			return nil, fmt.Errorf("EdDSA keygen cancelled")
		}
		return sess.GetPubKeyResult(), nil
	}
}
