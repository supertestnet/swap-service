import * as ws from "websocket";
var WebSocketClient = ws.default.client;
import * as bcipher from "browserify-cipher";
var browserifyCipher = bcipher.default;
import * as nobleSecp256k1 from "noble-secp256k1";
import * as cr from "crypto";
var crypto = cr.default;
var socket = new WebSocketClient();
import * as ax from "axios";
var axios = ax.default;
import * as bitcoinjs from "bitcoinjs-lib";
import * as rq from "request";
var request = rq.default;
import { ECPairFactory } from 'ecpair';
import * as tinysecp from 'tiny-secp256k1';
const ECPair = ECPairFactory(tinysecp);
import * as bolt11 from 'bolt11';

//testnet only

var invoicemac = "0201036C6E640258030A1041F7FF66DB876EE466CFD683452DE8C61201301A160A0761646472657373120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A0F0A076F6E636861696E12047265616400000620664FB824326207C2EBFE90C1716C7AE6FA074407E0960B24B482B20C2599BC6A";
var adminmac = "0201036C6E6402F801030A1043F7FF66DB876EE466CFD683452DE8C61201301A160A0761646472657373120472656164120577726974651A130A04696E666F120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A210A086D616361726F6F6E120867656E6572617465120472656164120577726974651A160A076D657373616765120472656164120577726974651A170A086F6666636861696E120472656164120577726974651A160A076F6E636861696E120472656164120577726974651A140A057065657273120472656164120577726974651A180A067369676E6572120867656E65726174651204726561640000062022840D6628EA0BFA93CB46BF26F60EB8FBB1497DBBAEBD55E269C6303DA063F4";
var lndendpoint = "http://localhost:7012";

//var privKey = "48af5b91b2eb1cab92c7243cf105adc39257fe986da28eb06c33faf3e8704ea7";
var privKey = ECPair.makeRandom().privateKey.toString( "hex" );
var pubKeyMinus2 = nobleSecp256k1.getPublicKey( privKey, true ).substring( 2 );
console.log( "my pubkey:", pubKeyMinus2 );
function normalizeRelayURL(e){let[t,...r]=e.trim().split("?");return"http"===t.slice(0,4)&&(t="ws"+t.slice(4)),"ws"!==t.slice(0,2)&&(t="wss://"+t),t.length&&"/"===t[t.length-1]&&(t=t.slice(0,-1)),[t,...r].join("?")}
//var relay = "wss://nostr.zebedee.cloud";
var relay = "ws://192.168.1.4:6969";
relay = normalizeRelayURL( relay );
var deal_in_progress = false;
var min_amount = 546;
var max_amount = 1000000;
var fee_type = `percentage`;
var fee = 5;

function getData( url ) {
	return new Promise( function( resolve, reject ) {
    	axios
    	.get( url )
    	.then( res => {
        	resolve( res.data );
    	}).catch( function( error ) {
            console.log( error.message );
        });
	});
}

function postData( url, json, headers ) {
    return new Promise( function( resolve, reject ) {
        axios
        .post( url, json, headers )
        .then( res => {
            resolve( res.data );
        }).catch( function( error ) {
            console.log( error.message );
        });
    });
}

async function getMinFeeRate() {
	var fees = await getData( "https://mempool.space/testnet/api/v1/fees/recommended" );
	if ( !( "minimumFee" in fees ) ) return "error -- site down";
	var minfee = fees[ "minimumFee" ];
	return minfee;
}

async function getBlockheight() {
    var data = await getData( "https://mempool.space/testnet/api/blocks/tip/height" );
    return Number( data );
}

function generateHtlc(serverPubkey, userPubkey, pmthash, timelock) {
   return bitcoinjs.script.fromASM(
        `
        OP_SHA256
        ${pmthash}
        OP_EQUAL
        OP_IF
        ${userPubkey}
        OP_ELSE
        ${bitcoinjs.script.number.encode(timelock).toString('hex')}
        OP_CHECKLOCKTIMEVERIFY
        OP_DROP
        ${serverPubkey}
        OP_ENDIF
        OP_CHECKSIG
        `
       .trim()
       .replace(/\s+/g, ' ')
   );
}

function getSwapAddress( serverPubkey, userPubkey, pmthash, timelock ) {
    var witnessscript = generateHtlc( serverPubkey, userPubkey, pmthash, timelock );
    var p2wsh = bitcoinjs.payments.p2wsh({redeem: {output: witnessscript, network: bitcoinjs.networks.testnet}, network: bitcoinjs.networks.testnet });
    return p2wsh.address;
}

function bytesToHex( bytes ) {
    return bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" );
}

function sha256( string ) {
	return crypto.createHash( "sha256" ).update( string ).digest( "hex" );
}

function encrypt( privkey, pubkey, text ) {
	var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
	var iv = Uint8Array.from( crypto.randomBytes( 16 ) )
	var cipher = browserifyCipher.createCipheriv(
    	'aes-256-cbc',
    	Buffer.from( key, 'hex' ),
    	iv
	);
    console.log( "latest error:", privkey, pubkey, text );
	var encryptedMessage = cipher.update( text, "utf8", "base64" );
	var emsg = encryptedMessage + cipher.final( "base64" );

	return emsg + "?iv=" + Buffer.from( iv.buffer ).toString( "base64");
}

function decrypt( privkey, pubkey, ciphertext ) {
	var [ emsg, iv ] = ciphertext.split( "?iv=" );
	var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
	var decipher = browserifyCipher.createDecipheriv(
    	'aes-256-cbc',
    	Buffer.from( key, "hex" ),
    	Buffer.from( iv, "base64" )
	);
	var decryptedMessage = decipher.update( emsg, "base64" );
	try {
		var dmsg = decryptedMessage + decipher.final( "utf8" );
	} catch( e ) {
		var dmsg = "error decrypting message -- the message was malformed";
	}

	return dmsg;
}

async function estimateExpiry( pmthash ) {
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight();
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestmap,
    var units_of_600 = 0;
    var i; for ( i=0; i<1008; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add 900 to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + 900;
/*
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( pmthash );
    var expiry_of_invoice_i_am_asked_to_pay = await get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice );
    var block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire = current_blockheight + Number( expiry_of_invoice_i_am_asked_to_pay );
    //abort if block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire > block_when_i_consider_the_invoice_that_pays_me_to_expire
    if ( Number( block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire ) > Number( block_when_i_consider_the_invoice_that_pays_me_to_expire ) ) {
        return "nice try, asking me to pay you when the invoice that pays me is about to expire";
    }
    //because that would mean the recipient can hold my payment til after the invoice that pays me expires
    //then he could settle my payment to him but leave me unable to reimburse myself (because the invoice that pays me expired)
    //also, when sending my payment, remember to set the cltv_limit value
    //it should be positive and equal to block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight
    var cltv_limit = block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight;
*/
    var returnable = {}
    return block_when_i_consider_the_invoice_that_pays_me_to_expire;
}

async function getHodlInvoice( amount, hash, expiry = 40 ) {
  var invoice = "";
  var macaroon = invoicemac;
  var endpoint = lndendpoint + "/v2/invoices/hodl";
  let requestBody = {
      hash: Buffer.from( hash, "hex" ).toString( "base64" ),
      value: amount.toString(),
      cltv_expiry: expiry.toString(),
  }
  let options = {
    url: endpoint,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify(requestBody),
  }
  request.post(options, function(error, response, body) {
    invoice = body[ "payment_request" ];
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( invoice );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( invoice );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function settleHoldInvoice( preimage ) {
  var settled = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let requestBody = {
      preimage: Buffer.from( preimage, "hex" ).toString( "base64" )
  }
  let options = {
    url: endpoint + '/v2/invoices/settle',
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify( requestBody ),
  }
  request.post( options, function( error, response, body ) {
    if ( body.toString().includes( "{" ) ) {
        settled = "true";
    } else {
        settled = "false";
    }
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( settled );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( settled );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;   
}

async function addressOnceSentMoney( address ) {
    var json = await getData( "https://mempool.space/testnet/api/address/" + address );
    if ( json[ "chain_stats" ][ "spent_txo_count" ] > 0 || json[ "mempool_stats" ][ "spent_txo_count" ] > 0 ) {
        return true;
    }
    return false;
}

async function loopTilAddressSendsMoney( address ) {
    var itSpentMoney = false;
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( !data_i_seek ) {
                setTimeout( async function() {
                    console.log( "checking for preimage in mempool..." );
                    itSpentMoney = await addressOnceSentMoney( address );
                    var msg = await isDataSetYet( itSpentMoney );
                    resolve( msg );
                }, 2000 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( itSpentMoney );
        return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function addressSentMoneyInThisTx( address, txid_of_deposit ) {
    var txid;
    var json = await getData( "https://mempool.space/testnet/api/address/" + address + "/txs" );
    json.forEach( function( tx ) {
        tx[ "vin" ].forEach( function( input ) {
            if ( input[ "txid" ] == txid_of_deposit ) {
                console.log( "txid that spent from the htlc:", tx[ "txid" ] );
                txid = tx[ "txid" ];
            }
        });
    });
    console.log( "double checking that I have the txid that spent from the htlc:", txid );
    return txid;
}

async function payHTLCAndSettleWithPreimage( invoice, htlc_address, amount ) {
    var txid_of_deposit = "";
    var users_pmthash = getinvoicepmthash( invoice );
    var state_of_held_invoice_with_that_hash = await checkInvoiceStatus( users_pmthash );
    if ( state_of_held_invoice_with_that_hash != "ACCEPTED" ) {
        deal_in_progress = false;
        var offer = {
            offer_id: ECPair.makeRandom().privateKey.toString('hex'),
            pubkey: ECPair.makeRandom().publicKey.toString('hex'),
            you_send: `lightning sats`,
            i_send: `base layer sats`,
            min_amount: min_amount,
            max_amount: max_amount,
            fee_type: fee_type,
            fee: fee,
        };
        setPublicNote( JSON.stringify(offer), relay );
        return "nice try, asking me to pay an invoice without compensation: " + state_of_held_invoice_with_that_hash;
    }
    var amount_i_will_receive = await getInvoiceAmount( users_pmthash );
    var amount_i_am_asked_to_pay = get_amount_i_am_asked_to_pay( invoice );
    if ( Number( amount_i_will_receive ) < Number( amount_i_am_asked_to_pay ) ) {
        return "nice try, asking me to send more than I will receive as compensation";
    }
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( users_pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight();
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestmap,
    var units_of_600 = 0;
    var i; for ( i=0; i<1008; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add 900 to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + 900;
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( users_pmthash );
    var adminmacaroon = adminmac;
    var endpoint = lndendpoint;
    var feerate = getMinFeeRate();
    let requestBody = {
        addr: htlc_address,
        amount: String( amount ),
        sat_per_byte: String( feerate )
    }
    let options = {
        url: endpoint + '/v1/transactions',
        json: true,
        headers: {
          'Grpc-Metadata-macaroon': adminmacaroon,
        },
        form: JSON.stringify( requestBody ),
    }
    request.post( options, function( error, response, body ) {
        txid_of_deposit = ( body[ "txid" ] );
        console.log( "body:", body );
        console.log( "txid_of_deposit:", txid_of_deposit );
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( txid );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( txid );
        return data_i_seek;
    }
    //todo: while looping, if address doesn't send money before timelock expires, sweep money back to self
    var itSentMoney = await loopTilAddressSendsMoney( htlc_address );
    var txid_that_sweeps_htlc = await addressSentMoneyInThisTx( htlc_address, txid_of_deposit );
    await waitSomeSeconds( 3 );
    var preimage_for_settling_invoice_that_pays_me = await getPreimageFromTransactionThatSpendsAnHTLC( txid_that_sweeps_htlc, users_pmthash );
    if ( preimage_for_settling_invoice_that_pays_me != "" ) {
        //preimage_for_settling_invoice_that_pays_me = Buffer.from( preimage_for_settling_invoice_that_pays_me, "base64" ).toString( "hex" );
        console.log( "preimage that pays me:", preimage_for_settling_invoice_that_pays_me );
        settleHoldInvoice( preimage_for_settling_invoice_that_pays_me );
        var returnable = '{"status": "success","preimage":"' + preimage_for_settling_invoice_that_pays_me + '"}';
    } else {
        var returnable = '{"status": "failure"}';
    }
    return returnable;
}

function waitSomeSeconds( num ) {
    var num = num.toString() + "000";
    num = Number( num );
    return new Promise( function( resolve, reject ) {
        setTimeout( function() { resolve( "" ); }, num );
    });
}


function get_amount_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var amount = decoded[ "satoshis" ].toString();
    return amount;
}

async function getInvoiceAmount( hash ) {
  var amount = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    amount = body[ "value" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( amount );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( amount );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatusWithoutLoop( hash ) {
  var status = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    status = body[ "state" ];
    console.log( "status:", status );
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( status );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( status );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatus( hash ) {
  var status = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    status = body[ "state" ];
    console.log( "status:", status );
  });
  var time = 0;
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek != "ACCEPTED" ) {
                          setTimeout( async function() {
                                  time = time + 1;
                                  console.log( "time:", time )
                                  if ( time == 1000 ) {
                                    resolve( "failure" );
                                    return;
                                  }
                                  console.log( "checking if buyer sent payment yet..." );
                                  status = await checkInvoiceStatusWithoutLoop( hash );
                                  var msg = await isDataSetYet( status );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( status );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getInvoiceCreationTimestamp( hash ) {
  var timestamp = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    timestamp = body[ "creation_date" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( timestamp );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( timestamp );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getInvoiceHardExpiry( hash ) {
  var expiry = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    expiry = body[ "cltv_expiry" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( expiry );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( expiry );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "min_final_cltv_expiry" ) {
            var cltv_expiry = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return cltv_expiry;
}

function getinvoicepmthash( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "payment_hash" ) {
            var pmthash = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return pmthash;
}

async function setNote( note, recipientpubkey, relay ) {
    var temp_socket = new WebSocketClient();
    var id = "";
    temp_socket.on( "error", function( error ) {
        console.log( "error:", error );
    });
    temp_socket.on( "connect", function( connection ) {
        function send( note, recipientpubkey ) {
            var now = Math.floor( ( new Date().getTime() ) / 1000 );
            var privatenote = encrypt( privKey, recipientpubkey, note );
            var newevent = [
                0,
                pubKeyMinus2,
                now,
                4,
                [['p', recipientpubkey]],
                privatenote
            ];
            var message = JSON.stringify( newevent );
            var msghash = sha256( message );
            nobleSecp256k1.schnorr.sign( msghash, privKey ).then(
                value => {
                    var sig = value;
                    nobleSecp256k1.schnorr.verify(
                        sig,
                        msghash,
                        pubKeyMinus2
                    ).then(
                        value => {
                            if ( value ) {
                                var fullevent = {
                                    "id": msghash,
                                    "pubkey": pubKeyMinus2,
                                    "created_at": now,
                                    "kind": 4,
                                    "tags": [['p', recipientpubkey]],
                                    "content": privatenote,
                                    "sig": sig
                                }
                                var sendable = [ "EVENT", fullevent ];
                                sendable = JSON.stringify( sendable );
                                connection.sendUTF( sendable );
                                id = msghash;
                                setTimeout( function() {connection.close();}, 300 );
                            }
                        }
                    );
                }
            );
        }
        send( note, recipientpubkey, relay );
    });
    temp_socket.connect( relay );
    async function isNoteSetYet( note_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( note_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isNoteSetYet( id );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( note_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var note_i_seek = await isNoteSetYet( id );
        return note_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function setPublicNote( note, relay ) {
    var temp_socket = new WebSocketClient();
    var id = "";
    temp_socket.on( "error", function( error ) {
        console.log( "error:", error );
    });
    temp_socket.on( "connect", function( connection ) {
        function send( note ) {
            var now = Math.floor( ( new Date().getTime() ) / 1000 );
            var newevent = [
                0,
                pubKeyMinus2,
                now,
                10042,
                [],
                note
            ];
            var message = JSON.stringify( newevent );
            var msghash = sha256( message );
            nobleSecp256k1.schnorr.sign( msghash, privKey ).then(
                value => {
                    var sig = value;
                    nobleSecp256k1.schnorr.verify(
                        sig,
                        msghash,
                        pubKeyMinus2
                    ).then(
                        value => {
                            if ( value ) {
                                var fullevent = {
                                    "id": msghash,
                                    "pubkey": pubKeyMinus2,
                                    "created_at": now,
                                    "kind": 10042,
                                    "tags": [],
                                    "content": note,
                                    "sig": sig
                                }
                                var sendable = [ "EVENT", fullevent ];
                                sendable = JSON.stringify( sendable );
                                connection.sendUTF( sendable );
                                id = msghash;
                                setTimeout( function() {connection.close();}, 300 );
                            }
                        }
                    );
                }
            );
        }
        send( note, relay );
    });
    temp_socket.connect( relay );
    async function isNoteSetYet( note_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( note_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isNoteSetYet( id );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( note_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var note_i_seek = await isNoteSetYet( id );
        return note_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

function isValidAddress( address ) {
    try{
        return ( typeof( bitcoinjs.address.toOutputScript( address, bitcoinjs.networks.testnet ) ) == "object" );
    } catch( e ) {
        return;
    }
}

async function getPreimageFromTransactionThatSpendsAnHTLC( txid, pmthash ) {
    var json = await getData( "https://mempool.space/testnet/api/tx/" + txid );
    var i; for ( i=0; i<json[ "vin" ].length; i++ ) {
        var j; for ( j=0; j<json[ "vin" ][ i ][ "witness" ].length; j++ ) {
            if ( bitcoinjs.crypto.sha256( Buffer.from( json[ "vin" ][ i ][ "witness" ][ j ], "hex" ) ).toString( "hex" ) == pmthash ) {
                console.log( "preimage I am passing in:", json[ "vin" ][ i ][ "witness" ][ j ] );
                console.log( "payment hash I am checking against:", pmthash );
                console.log( "payment hash I get when I hash the supposed preimage:", bitcoinjs.crypto.sha256( Buffer.from( json[ "vin" ][ i ][ "witness" ][ j ], "hex" ) ).toString( "hex" ) );
                return json[ "vin" ][ i ][ "witness" ][ j ];
            }
        }
    }
}

var offers = {};

socket.on( 'connect', async function( connection ) {
	console.log( "connected to nostr relay " + relay );
	connection.on( 'error', function( error ) {
    	console.log( error );
	});
	connection.on( 'message', async function( message ) {
        var [type, subId, event] = JSON.parse(message.utf8Data);
        var { kind, content } = event || {};
        if (!event) return;
        console.log( "event:", event );
        if (kind === 10042) {
          if (!content) return;
          var offerContent = JSON.parse(content);
          offers = {};
          offers[offerContent.offer_id] = offerContent;

          console.log('offers:', offers);
        }

        if (kind === 4) {
          if ( deal_in_progress ) return;
          var accept = decrypt(privKey, event.pubkey, content)
          //console.log(`we get:`, accept, event.pubkey);

          if (!isValidJson(accept)) return;
          //console.log(`valid jSON`);
          var acceptJSON = JSON.parse(accept);
          if (Object.keys(acceptJSON).length !== 5) return;
          //console.log(`JSON accepted:`, Object.keys(acceptJSON));
          // console.log(
          //   typeof acceptJSON['hash'],
          //   typeof acceptJSON['script_address'],
          //   typeof acceptJSON['pubkey']
          // );

          var jsonAmount = acceptJSON['amount'];
          var jsonHash = acceptJSON['hash'];
          var jsonAddress = acceptJSON['script_address'];
          var jsonPubkey = acceptJSON['pubkey'];

          if (!jsonAmount) return;
          if (typeof jsonAmount !== 'number') return;

          if (!jsonHash) return;
          if (typeof jsonHash !== 'string') return;
          if (jsonHash.length !== 64) return;
          if (!isHex(jsonHash)) return;

          if (!jsonAddress) return;
          if (typeof jsonAddress !== 'string') return;
          if (!isValidAddress(jsonAddress)) return;

          if (!jsonPubkey) return;
          if (typeof jsonPubkey !== 'string') return;
          if (jsonPubkey.length !== 66) return;

          var eventContent = JSON.parse( accept );
          //console.log( "timestamp:", Date( event.created_at ).toLocaleString(), "now minus ten:", Date( Math.floor( Date.now() / 1000 ) - 600 ).toLocaleString() );
          var blockHeight = await getBlockheight();
          var timelock = blockHeight + 10;
          //console.log(offers + eventContent.offer_id);
          try {
            var offerPubkey = offers[eventContent.offer_id]['pubkey'];            
          } catch( e ) {
            return "no matching pubkey, you probably restarted the app";
          }
          //now we validate that the acceptance message is within the ranges
          //offered by our offer
          if ( jsonAmount < offers[eventContent.offer_id]['min_amount'] ) return;
          if ( jsonAmount > offers[eventContent.offer_id]['max_amount'] ) return;
          console.log(`we passed the test`);
          // console.log(
          //   offerPubkey,
          //   eventContent.pubkey,
          //   eventContent.hash,
          //   timelock
          // );
          var witness_script = generateHtlc(
            offerPubkey,
            eventContent.pubkey,
            eventContent.hash,
            timelock
          );
          var p2wsh = bitcoinjs.payments.p2wsh({
            redeem: { output: witness_script, network: bitcoinjs.networks.testnet },
          });
          console.log('swap address:', p2wsh.address);
          if ( jsonAddress !=  p2wsh.address ) {
            console.log( "oh no! The addresses didn't match. They sent this one:", jsonAddress, "but I got this one:", p2wsh.address );
            return;
          }
          // console.log(`acceptance`);
          deal_in_progress = true;
          //replace offer with a blank one so that people don't accept it twice
          var offerEvent = {
              content: "",
              created_at: Math.floor(Date.now() / 1000),
              kind: 10042,
              tags: [],
              pubkey: pubKeyMinus2,
          };
          var signedOffer = await getSignedEvent(offerEvent, privKey);
          console.log( "signed offer:", signedOffer );
          connection.sendUTF( JSON.stringify( [ "EVENT", signedOffer ] ) );

          if ( fee_type === 'absolute' ) {
            var post_fee_amount = jsonAmount + fee;
          } else {
            var post_fee_amount = jsonAmount * ( ( 100 + fee ) / 100 );
          }
          var swap_invoice = await getHodlInvoice( post_fee_amount, jsonHash, 40 );
          console.log( "swap_invoice:", swap_invoice );
          var note = setNote( swap_invoice, event.pubkey, relay );
          var message = await payHTLCAndSettleWithPreimage( swap_invoice, p2wsh.address, jsonAmount );
          console.log( message );
          deal_in_progress = false;
        }
	});
    var timestamp = Math.floor(Date.now() / 1000);
    var timeMinusTen = timestamp - 600;
    var subId = ECPair.makeRandom().privateKey.toString( "hex" );
    var filter = { kinds: [4], since: timeMinusTen };
    var filter2 = { kinds: [10042], authors: [pubKeyMinus2], since: timeMinusTen };
    var subscription = [ "REQ", subId, filter, filter2 ];
    subscription = JSON.stringify( subscription );
	setTimeout( function() {connection.sendUTF( subscription );}, 1000 );

    async function sendOffer() {
        var offer = {
            offer_id: ECPair.makeRandom().privateKey.toString('hex'),
            pubkey: ECPair.makeRandom().publicKey.toString('hex'),
            min_amount: min_amount,
            max_amount: max_amount,
            fee_type: fee_type,
            fee: fee,
        };

        var offerEvent = {
            content: JSON.stringify(offer),
            created_at: Math.floor(Date.now() / 1000),
            kind: 10042,
            tags: [],
            pubkey: pubKeyMinus2,
        };

        var signedOffer = await getSignedEvent(offerEvent, privKey);
        console.log( "signed offer:", signedOffer );
        connection.sendUTF( JSON.stringify( [ "EVENT", signedOffer ] ) );
        if ( !deal_in_progress ) setTimeout( function() {sendOffer();}, 1000 * 60 * 10 );
    }
    sendOffer();
});

socket.connect( relay );

function isValidJson( content ) {
	if ( !content ) return;
	try {  
    	var json = JSON.parse( content );
	} catch ( e ) {
    	return;
	}
	return true;
}

function isHex( h ) {
    var length = h.length;
    if ( length % 2 ) return;
    if ( length > 66 ) return;
    var a = BigInt( "0x" + h, "hex" );
    var unpadded = a.toString( 16 );
    var padding = "000000000000000000000000000000000000000000000000000000000000000000";
    padding = padding + unpadded.toString();
    padding = padding.slice( -Math.abs( length ) );
    return ( padding === h );
}

async function getSignedEvent(event, privateKey) {
    var eventData = JSON.stringify([
        0, // Reserved for future use
        event['pubkey'], // The sender's public key
        event['created_at'], // Unix timestamp
        event['kind'], // Message ???kind??? or type
        event['tags'], // Tags identify replies/recipients
        event['content'], // Your note contents
    ]);
    event.id = bitcoinjs.crypto.sha256(eventData).toString('hex');
    event.sig = await nobleSecp256k1.schnorr.sign(event.id, privateKey);
    return event;
}
