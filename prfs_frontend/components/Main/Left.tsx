import React from "react";
import axios from "axios";
import { ethers } from 'ethers';
import Web3 from 'web3';

import styles from "./Left.module.scss";

const Left = (props: any) => {
  const [proof, setProof] = React.useState("");

  const handleClickGenProof = React.useCallback(async () => {
    const fetchData = async () => {
      console.log('fetch data');

      let accounts = await window.ethers.send('eth_requestAccounts', []);

      if (accounts != null && Array.isArray(accounts)) {
        const account = accounts[0];
        console.log('account', account);

        let u = ethers.utils;
        let signer = window.ethers.getSigner();

        const ethAddress = await signer.getAddress();
        console.log('ethAddress', ethAddress);

        const message_raw = 'test';
        const message_hash = u.hashMessage(message_raw);
        console.log('message hash', message_hash);

        const signature = await signer.signMessage(message_raw);
        console.log('signature', signature, signature.length);

        const digest = u.arrayify(message_hash);

        const public_key = u.recoverPublicKey(digest, signature);
        console.log('recovered publickey', public_key);

        const computedAddress = u.computeAddress(public_key);
        console.log('computed address', computedAddress);

        const recoveredAddress = u.recoverAddress(digest, signature)
        console.log('recovered address', recoveredAddress);

        let { data } = await axios.post("http://localhost:4000/gen_proof", {
          address: account,
          public_key,
          proof_type: 'asset_proof_1',
          signature,
          path: [],
          leaf_idx: 0,
          root: '',
          message_raw,
          message_hash,
        });

        console.log('axios response', data);
        setProof(data.proof.join(","));
      }
    };

    fetchData().then((_res) => { });
  }, [setProof]);

  return (
    <div className={styles.wrapper}>
      <div className={styles.leftLabel}></div>
      <button onClick={handleClickGenProof}>Generate proof</button>
      <div className={styles.desc}>
        Currently the only proof we support generating is <i>Asset proof</i>
      </div>
      <div>{proof}</div>
    </div>
  );
};

export default Left;
