import React from "react";
import axios from "axios";
import { ethers } from 'ethers';

import styles from "./Left.module.scss";

const Left = (props: any) => {
  const [proof, setProof] = React.useState("");

  const handleClickGenProof = React.useCallback(async () => {
    const fetchData = async () => {
      console.log('fetch data');

      let accounts = await window.ethers.send('eth_requestAccounts', []);

      if (accounts != null && Array.isArray(accounts)) {
        const account = accounts[0];
        let signer = window.ethers.getSigner();
        let msg_hash = ethers.utils.hashMessage('msg_hash');

        const digest = ethers.utils.arrayify(msg_hash);
        let signature = await signer.signMessage(digest);

        let s = ethers.utils.arrayify(signature);
        let public_key = ethers.utils.recoverPublicKey(digest, s);

        console.log('account', account);
        console.log('public_key', public_key);
        console.log('signature', signature);
        console.log('msg_hash', msg_hash);

        await axios.post("http://localhost:4000/gen_proof", {
          address: account,
          public_key,
          proof_type: 'asset_proof_1',
          signature,
          path: [],
          leaf_idx: 0,
          root: '',
          msg_hash,
        });

        // console.log(22, data);

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
