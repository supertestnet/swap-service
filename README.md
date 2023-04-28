# Swap service
An orderbook for performing submarine swaps over nostr

# How can I try it?

Go here for mainnet: https://supertestnet.github.io/swap-service/

Or here for testnet: https://supertestnet.github.io/swap-service/testnet.html

# Video

[![](https://supertestnet.github.io/swap-service/swap-service-screenshot-with-youtube-logo.png)](https://www.youtube.com/watch?v=mVWufwzQ_RI)

# Instructions for yield chasers

[Click here](#installation) if you have a lightning node and want to use this tool to earn some money and accrue yield on your bitcoin

# What problem does this solve?

Submarine swaps can't be a profitable way for plebs to monetize their bitcoin holdings unless there are simple tools for offering them for a fee. Swap service tries to be an easy tool for anyone to do that.

# What is a submarine swap?

Submarine swaps are an important feature of the lightning network. They allow lightning users to swap funds on lightning for funds on the base layer, or vice versa, without needing to open and close channels, and without needing to give custody of their money to other people. They also allow easier channel rebalancing and they are also the basis for important wallets and services like muun, lightning loop, and boltz exchange.

However, there are not very many submarine swap providers. Sometimes I wonder if the ones who exist are overcharging, and I also just think it would be cool if anyone could profit by offering submarine swaps easily from their own lightning node. With lots of participants, costs may be driven down close to zero.

# How does swap service work?

Anyone who runs an LND lightning node can run swap service on their computer and hook it up to their node. This makes them a yield chaser. As a yield chaser, you can set a few parameters like how many sats you are willing to swap, how much you have on the base layer, how much you have on lightning, and what fee you'll charge for swaps. When you're ready, swap service will take your settings and display them as an offer on an open orderbook I created on nostr. Other folks can visit a simple website to view everyone's offers. They can also select an offer and initiate a swap. During the course of the swap, they will pay the yield chaser they selected a fee to do a submarine swap with them. The yield chaser gets to keep the fee.

# So I can use this to make money?

Yes. Lightning Labs has been doing it for a long time through their lightning loop service. So has boltz exchange. But it's been hard for plebs to do it on their own node, partly because submarine swaps require network coordination, partly because discovery is challenging, and partly because there wasn't great software for it. But nostr lets me fix the first two problems (network coordination and discovery) so now we just need decent software for it. Hopefully swap service is at least a start.

# Installation

First clone this github repo: `git clone https://github.com/supertestnet/swap-service.git`

Then enter the directory and turn it into a nodejs app: `cd swap-service && npm init -y`

Install the dependencies: `npm i websocket browserify-cipher noble-secp256k1 axios bitcoinjs-lib request ecpair tiny-secp256k1 bolt11`

Open the index.js file (or the testnet.js file) in a text editor: `nano index.js` (or `nano testnet.js`)

Modify the first few lines:

```
var invoicemac = "";
var adminmac = "";
var lndendpoint = ""; //e.g. https://127.0.0.1:8080 or https://cloud-59.voltage.com
var min_amount = 546;
var max_amount = 1000000;
var fee_type = "percentage"; //alternative: "absolute"
var fee = 5; //if fee type is absolute, this integer is a flat rate, e.g. you will get 5 sats per swap; otherwise you get a rate corresponding to e.g. 5% of each swap
```

You can get your admin macaroon and invoice macaroon from tools like Thunderhub or Voltage Cloud. Paste them in between the quotation marks where it says `invoicemac = ""` and `adminmac = ""`. In nano, you can usually paste with one of these two commands: `right-click+paste` or `shift + insert`.

Save your file: `hit ctrl+o (that's an o as in output not a 0) and then, after about half a second, hit the enter key`

Run the app: `node index.js` (or `node testnet.js`)

And you're done! Your node should automatically perform submarine swaps with anyone who accepts your offer and you will earn fees for it.

> Pro tip: ensure you set your minimum amount and your fee to a profitable value. If your minimum is only 546 sats (bitcoin's dust limit) then you will sometimes spend more in mining fees then you'll gain from service fees. That is because the cost of a mining fee to send someone sats on the base layer is typically about 200 sats times whatever the current feerate is (e.g. 3 sats per byte, 10 sats per byte, or 25 sats per byte). So your fee expense might be up to 200\*25 = 5000 sats, even though you're only sending someone 546 sats. If your fee revenue is only 5 percent of 546 sats (546\*.05=27 sats) but your expense is 5000 sats, you will lose money. So be sure to set reasonably large values for min_amount and fee, but not so high that no one wants to use your service because it's too expensive.
