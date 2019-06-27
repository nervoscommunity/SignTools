
<template>
  <el-container>
    <el-main>
      <img src="../assets/NC-logo-words.png" style='width:40%;'>
      <p>Nervos签名生成工具</p>
      <div style="margin-top: 20px">
        <el-input
          type="textarea"
          :rows="2"
          placeholder="请输入你要签名的信息"
          v-model="msg">
        </el-input>
      </div>
      <div style="margin-top: 20px">
        <el-input v-model="privatekey" placeholder="请输入私钥"  show-password></el-input>
      </div>
      <div style="margin-top: 20px">
          <el-button type="success" id="button" @click='sign(privatekey,msg)' round>签名</el-button>
      </div>
      <div v-if='signedmsg' style="margin-top: 25px">
        <p>签名信息:</p>
        <el-input type="textarea"
          :rows="2"
          v-model="signedmsg" 
          :disabled="true">
        </el-input>
        <p>请妥善保管您的私钥，NervosCommunity不会以任何形式索要您的私钥。</p>
      </div>
    </el-main>
  </el-container>
</template>

<script>
/* eslint-disable */
export default {
  data(){
    return {
      privatekey:'',
      msg:'',
      signedmsg:'',
    }
  },
  methods: {
    sign:function(privatekey,usermsg){
      if(!privatekey&&!usermsg){
        this.$message({
          type: 'warning',
          message: '请输入私钥和签名'
        });
        return
      }
      let elliptic = require('elliptic');
      let sha3 = require('js-sha3');
      let ec = new elliptic.ec('secp256k1');

      // let keyPair = ec.genKeyPair();
      let keyPair = ec.keyFromPrivate(privatekey);
      let privKey = keyPair.getPrivate("hex");
      let pubKey = keyPair.getPublic();
      // console.log(`Private key: ${privKey}`);
      // console.log("Public key :", pubKey.encode("hex").substr(2));
      // console.log("Public key (compressed):",
      pubKey.encodeCompressed("hex");
      console.log();
      let msgHash = sha3.keccak256(usermsg);
      let signature = ec.sign(msgHash, privKey, "hex", {canonical: true});
      // console.log(`Msg: ${usermsg}`);
      // console.log(`Msg hash: ${msgHash}`);
      // console.log("Signature:", signature);
      this.signedmsg = msgHash;

      this.$message({
          type: 'info',
          message: '签名成功'
        });
      let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
      let pubKeyRecovered = ec.recoverPubKey(
          hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
      // console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));
      let validSig = ec.verify(msgHash, signature, pubKeyRecovered);
      // console.log("Signature valid?", validSig);
    }
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
#button{
  width: 20%;
}

</style>
