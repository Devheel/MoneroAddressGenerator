var crc32 = require("./crc32");
var cnUtilGen = require("./cnUtilGen")

var moneroConfig = {
    coinUnitPlaces: 12,
    coinSymbol: 'XMR',
    coinName: 'Monero',
    coinUriPrefix: 'monero:',
    addressPrefix: 18
};
var aeonConfig = {
    coinUnitPlaces: 12,
    coinSymbol: 'AEON',
    coinName: 'Aeon',
    coinUriPrefix: 'aeon:',
    addressPrefix: 0xB2
};

var cnUtil = cnUtilGen(moneroConfig);
var mn_default_wordset = 'english';

function mn_get_checksum_index(words, prefix_len) {
    var trimmed_words = "";
    for (var i = 0; i < words.length; i++) {
        trimmed_words += words[i].slice(0, prefix_len);
    }
    var checksum = crc32.run(trimmed_words);
    var index = checksum % words.length;
    return index;
}
function mn_encode(str, wordset_name) {
    'use strict';
    wordset_name = wordset_name || mn_default_wordset;
    var wordset = mn_words[wordset_name];
    var out = [];
    var n = wordset.words.length;
    for (var j = 0; j < str.length; j += 8) {
        str = str.slice(0, j) + mn_swap_endian_4byte(str.slice(j, j + 8)) + str.slice(j + 8);
    }
    for (var i = 0; i < str.length; i += 8) {
        var x = parseInt(str.substr(i, 8), 16);
        var w1 = (x % n);
        var w2 = (Math.floor(x / n) + w1) % n;
        var w3 = (Math.floor(Math.floor(x / n) / n) + w2) % n;
        out = out.concat([wordset.words[w1], wordset.words[w2], wordset.words[w3]]);
    }
    if (wordset.prefix_len > 0) {
        out.push(out[mn_get_checksum_index(out, wordset.prefix_len)]);
    }
    return out.join(' ');
}
function mn_swap_endian_4byte(str) {
    'use strict';
    if (str.length !== 8) throw 'Invalid input length: ' + str.length;
    return str.slice(6, 8) + str.slice(4, 6) + str.slice(2, 4) + str.slice(0, 2);
}
function mn_decode(str, wordset_name) {
    'use strict';
    wordset_name = wordset_name || mn_default_wordset;
    var wordset = mn_words[wordset_name];
    var out = '';
    var n = wordset.words.length;
    var wlist = str.split(' ');
    var checksum_word = '';
    if (wlist.length < 12) throw "You've entered too few words, please try again";
    if ((wordset.prefix_len === 0 && (wlist.length % 3 !== 0)) ||
        (wordset.prefix_len > 0 && (wlist.length % 3 === 2))) throw "You've entered too few words, please try again";
    if (wordset.prefix_len > 0 && (wlist.length % 3 === 0)) throw "You seem to be missing the last word in your private key, please try again";
    if (wordset.prefix_len > 0) {
        // Pop checksum from mnemonic
        checksum_word = wlist.pop();
    }
    // Decode mnemonic
    for (var i = 0; i < wlist.length; i += 3) {
        var w1, w2, w3;
        if (wordset.prefix_len === 0) {
            w1 = wordset.words.indexOf(wlist[i]);
            w2 = wordset.words.indexOf(wlist[i + 1]);
            w3 = wordset.words.indexOf(wlist[i + 2]);
        } else {
            w1 = wordset.trunc_words.indexOf(wlist[i].slice(0, wordset.prefix_len));
            w2 = wordset.trunc_words.indexOf(wlist[i + 1].slice(0, wordset.prefix_len));
            w3 = wordset.trunc_words.indexOf(wlist[i + 2].slice(0, wordset.prefix_len));
        }
        if (w1 === -1 || w2 === -1 || w3 === -1) {
            throw "invalid word in mnemonic";
        }
        var x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);
        if (x % n != w1) throw 'Something went wrong when decoding your private key, please try again';
        out += mn_swap_endian_4byte(('0000000' + x.toString(16)).slice(-8));
    }
    // Verify checksum
    if (wordset.prefix_len > 0) {
        var index = mn_get_checksum_index(wlist, wordset.prefix_len);
        var expected_checksum_word = wlist[index];
        if (expected_checksum_word.slice(0, wordset.prefix_len) !== checksum_word.slice(0, wordset.prefix_len)) {
            throw "Your private key could not be verified, please try again";
        }
    }
    return out;
}
var mn_words = require("./words");
for (var i in mn_words) {
    if (mn_words.hasOwnProperty(i)) {
        if (mn_words[i].prefix_len === 0) {
            continue;
        }
        mn_words[i].trunc_words = [];
        for (var j = 0; j < mn_words[i].words.length; ++j) {
            mn_words[i].trunc_words.push(mn_words[i].words[j].slice(0, mn_words[i].prefix_len));
        }
    }
}

require('./algos');

function poor_mans_kdf(str)
{
  var hex = cnBase58.bintohex(cnBase58.strtobin(str));
  for (var n = 0; n < 10000; ++n)
    hex = keccak_256(cnBase58.hextobin(hex));
  return hex;
}
current_lang='english';
keys = null;
function genwallet(lang)
{
  var wallet = {};

  if (lang!=null) {
    current_lang = lang;
  }
  seed = cnUtil.sc_reduce32(cnUtil.rand_32());
  keys = cnUtil.create_address(seed);

  mnemonic = mn_encode(seed,current_lang);
  // console.log('getWallet', {keys: keys, address: cnUtil.pubkeys_to_string(keys.spend.pub, keys.view.pub), mnemonic: mnemonic});
  return {
    address: cnUtil.pubkeys_to_string(keys.spend.pub, keys.view.pub),
    mnemonic: mnemonic
  }
}

previous_button_text = "";
prefix = "";
function genwallet_prefix_worker()
{
  attempts = 0;
  while (true) {
    attempts++;
    seed = cnUtil.sc_reduce32(cnUtil.rand_32());
    keys = cnUtil.create_address_if_prefix(seed,prefix);
    if (keys != null) {
      gen_prefix_widget = document.getElementById("gen_prefix_widget");
      prefix_widget = document.getElementById("prefix_widget");
      gen_prefix_widget.value = previous_button_text;
      prefix_widget.disabled = false;
      generating = false;
      break;
    }
    if (attempts == 10) {
      if (generating)
        setTimeout(genwallet_prefix_worker, 0);
      return;
    }
  }
  mnemonic = mn_encode(seed,current_lang);

  spend_key_widget = document.getElementById("spend_key_widget");
  view_key_widget = document.getElementById("view_key_widget");
  address_widget = document.getElementById("address_widget");
  mnemonic_widget = document.getElementById("mnemonic_widget");

  spend_key_widget.innerHTML = keys.spend.sec;
  view_key_widget.innerHTML = keys.view.sec;
  address_widget.innerHTML = keys.public_addr;
  address_qr_widget.innerHTML = "";
  mnemonic_widget.innerHTML = mnemonic;

  qr=new QRCode(address_qr_widget, {correctLevel:QRCode.CorrectLevel.L});
  qr.makeCode("monero:"+keys.public_addr);
}

var zerohex="0000000000000000000000000000000000000000000000000000000000000000";
var ffhex="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

function is_valid_prefix(prefix)
{
  if (prefix.length <= 0 || prefix.length >= 95)
    return false;
  var lowest_address=cnUtil.pubkeys_to_string(zerohex,zerohex);
  var highest_address=cnUtil.pubkeys_to_string(ffhex,ffhex);
  var lowest=lowest_address.substr(0,prefix.length);
  var highest=highest_address.substr(0,prefix.length);
  if (prefix<lowest)
    return false;
  if (prefix>highest)
    return false;
  return true;
}

function check_prefix_validity()
{
  gen_prefix_widget = document.getElementById("gen_prefix_widget");
  prefix_widget = document.getElementById("prefix_widget");
  if (gen_prefix_widget.value == "STOP")
    return;
  prefix=prefix_widget.value;
  if (is_valid_prefix(prefix)) {
    gen_prefix_widget.value = "Generate wallet with prefix";
    gen_prefix_widget.disabled = false;
  }
  else {
    gen_prefix_widget.value = "Invalid prefix";
    gen_prefix_widget.disabled = true;
  }
}

generating = false;
function genwallet_prefix()
{
  gen_prefix_widget = document.getElementById("gen_prefix_widget");
  prefix_widget = document.getElementById("prefix_widget");
  if (generating) {
    generating = false;
    gen_prefix_widget.value = previous_button_text;
    prefix_widget.disabled = false;
  }
  else {
    prefix_widget = document.getElementById("prefix_widget");
    prefix = prefix_widget.value;
    prefix.trim();
    if (prefix.length < 2) {
      alert("Bad prefix should be at least two characters");
      return;
    }
    if (!is_valid_prefix(prefix)) {
      alert("Bad prefix "+prefix+" is not a valid address prefix");
      return;
    }

    generating = true;
    previous_button_text = gen_prefix_widget.value;
    gen_prefix_widget.value = "STOP";
    prefix_widget.disabled = true;
    setTimeout(genwallet_prefix_worker, 0);
  }
}

function checkEntropy()
{
  var good = true;
  var button = document.getElementById("gen_with_custom_entropy_button")
  var user_entropy_widget = document.getElementById("user_entropy_widget")
  var user_entropy = user_entropy_widget.value;
  var user_entropy_warning_widget = document.getElementById("user_entropy_warning_widget")
  if (user_entropy.length === 0) {
    user_entropy_warning_widget.style.display = "none"
    return
  }

  var count = new Int32Array(256);
  for (var n = 0; n < 256; ++n)
    count[n] = 0
  for (var n = 0; n < user_entropy.length; ++n)
    count[user_entropy.charCodeAt(n)]++;
  var e = 0
  for (var n = 0; n < 256; ++n) {
    if (count[n] > 0) {
      var p = count[n] / user_entropy.length
      p *= Math.log(p) / Math.log(2)
      e -= p
    }
  }
  e *= user_entropy.length
  if (e < 128)
    good = false
  if (good)
    user_entropy_warning_widget.style.display = "none"
  else
    user_entropy_warning_widget.style.display = "block"
}

module.exports = genwallet;