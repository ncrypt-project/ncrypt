
/* nCrypt - Javascript cryptography made simple
 * Copyright (C) 2021 ncrypt-project
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

module.exports = (function(ncrypt, dep){

/**
 * @namespace nCrypt.asym.simple.message
 * */
var  message = {};
var _message = {};

var tsecret = dep.types.basic.secret;
var tid = dep.types.basic.id;
var tdh = dep.types.shared.dh;
var tecies = dep.types.shared.ecies;
var tkeypair = dep.types.key.keypair;
var tkeyset = dep.types.simple.keyset;
var tsign = dep.types.signature.ecdsa; // tsign.Signature
var tsymkey = dep.types.simple.message.symkey;

var SecureExec = ncrypt.dep.SecureExec;
var _isExp = SecureExec.tools.proto.inst.isException;

_message.typesArray = [ 1, 2, 3 ];
_message.types = {
    "ENCRYPT": 1,
    "SIGN": 2,
    "BOTH": 3
};

/**
 * @namespace nCrypt.asym.simple.message.types
 * */
message.types = {};

/**
 * Get the possible types a message might have. These types can be seen as 
 * constants and are found in the message JSON.
 * @returns {object}
 * @function
 * @name getTypes
 * @memberof nCrypt.asym.simple.message.types
 * */
message.types.getTypes = function(){
    return JSON.parse(JSON.stringify(_message.types));
};

_message.sender = {};

_message.sender.process = {};
_message.sender.process.encrypt = 
function(cleartext, enc_symkey_args, sender_ks, 
         symkey_secret, sym_alg, sym_opts, callback, carry)
{
    var task_precheck_esk = function(cb, args){
        var esk = args.enc_symkey_args;
        if(typeof esk!=='object' || !Array.isArray(esk)){
            cb(args); return; // will result in invalid receiver array in check
        }
        var esk_is_json_arr = true;
        for(var i=0; i<esk.length; i++){
            var o = esk[i];
            if(typeof o!=='object' ||
               typeof o.t!=='string' ||
               typeof o.i!=='string' ||
               typeof o.k!=='object' ||
               ((typeof o.t==='string' && o.t==='ecies') && 
                (typeof o.tag!=='object' || o.tag===null || o.tag==={})) )
            {
                esk_is_json_arr = false; break;
            }
        }
        if(esk_is_json_arr!==true){
            tsymkey.sender.arr.createEncryptedSymkeyArray(
                esk.slice(0), args.symkey_secret, args.sym_alg, args.sym_opts,
                function(arr, c){
                    var args = c.a;
                    var cb = c.c;
                    if(_isExp(arr)){ cb(arr); return; }
                    arr = tsymkey.sender.arr.symkeyArrayJSON(arr);
                    if(_isExp(arr)){ cb(arr); return; }
                    args.enc_symkey_args = arr.slice(0);
                    cb(args); return;
                }, 
                { 'a': args, 'c': cb }
            );
        }else{ cb(args); return; }
    };
    var task_check_args = function(cb, args){
        var runf = function(args){
            /* Validate cleartext */
            if(typeof args.cleartext!=='string' || args.cleartext.length<1){
                throw (new ncrypt.exception.types.simple.message.
                        message.invalidArgument());
            }
            
            /* Validate symmetric keys object */
            var clone_enc_symkey_args_json = [];
            if(typeof args.enc_symkey_args !=='object' || 
               !Array.isArray(args.enc_symkey_args)){
                throw (new ncrypt.exception.types.simple.message.message.
                    invalidReceiverArray());
            }
            for(var i=0; i<args.enc_symkey_args.length; i++){
                var o = args.enc_symkey_args[i];
                if(typeof o!=='object' ||
                   typeof o.t!=='string' ||
                   typeof o.i!=='string' ||
                   typeof o.k!=='object' ||
                   ((typeof o.t==='string' && o.t==='ecies') && 
                    (typeof o.tag!=='object' || o.tag===null || o.tag==={})) )
                {
                    throw (new ncrypt.exception.types.simple.message.message.
                    invalidReceiverArray());
                }
                try{
                    // clone_enc_symkey_args_json
                    o = JSON.parse(JSON.stringify(o));
                    clone_enc_symkey_args_json.push(o);
                }catch(e){
                    throw (new ncrypt.exception.types.simple.message.message.
                    invalidReceiverArray());
                }
            }
            args.enc_symkey_args = clone_enc_symkey_args_json; 
            
            /* Validate sender keyset */
            if(typeof args.sender_ks==='object'){
                try{
                    args.sender_ks = args.sender_ks.clone();
                    if(_isExp(args.sender_ks)) return args.sender_ks;
                }catch(e){ throw (new ncrypt.exception.types.simple.message.
                        message.invalidArgument());
                }
            }else if(typeof args.sender_ks==='string'){
                args.sender_ks = tkeyset.pub.getPublicKeyset(args.sender_ks);
                args.sender_ks = new tkeyset.Keyset(args.sender_ks);
                if(_isExp(args.sender_ks)) return args.sender_ks;
            }else{
                throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
            }
            
            /* Validate symmetric key */
            if(typeof args.symkey_secret==='object'){
                try{
                    args.symkey_secret = args.symkey_secret.getSecretValue();
                }catch(e){}
            }
            args.symkey_secret = new tsecret.Secret(tsecret.source.SECRET,
                                    args.symkey_secret);
            if(_isExp(args.symkey_secret)) return args.symkey_secret;
            
            /* Validate @sym_alg */
            if(typeof args.sym_alg !=='string' || args.sym_alg.length<1 ||
               ncrypt.sym.getAvailable().indexOf(args.sym_alg)<0){
                throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
            }
            
            /* Validate @sym_opts */
            if(typeof args.sym_opts!=='undefined'){
                if(typeof args.sym_opts!=='object'){
                    throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
                }
                if(args.sym_opts === null) args.sym_opts = {};
            }
            return args;
        };
        args = SecureExec.sync.apply(runf, [args]);
        cb(args);
    };//var check_args
    var task_encrypt_cleartext = function(cb, args){
        var salg = args.sym_alg;
        var sopts = args.sym_opts;
        var cleartext = args.cleartext;
        var pass = args.symkey_secret.getSecretValue();
        ncrypt.sym.async.encrypt(cleartext, pass, salg, function(ct, a){
            var args = a.a;
            var cb = a.c;
            if(_isExp(ct)){ cb(ct); return; }
            args.ciphertext = ct;
            try{
                args.ciphertext = JSON.parse(args.ciphertext);
            }catch(e){
                cb(new SecureExec.exception.Exception(null,null,e));
                return;
            }
            cb(args);
        }, {'a': args, 'c': cb }, sopts);
    };
    var task_get_sender_id = function(cb, args){
        args.sender_id = args.sender_ks.getPublicKeyIDs().txt.normal+'';
        cb(args);
    };
    var task_assemble_msg = function(cb, args){
        try{
            var ct = JSON.parse(JSON.stringify(args.ciphertext));
        }catch(e){ 
            var exp = new SecureExec.exception.Exception(null,null,e);
            cb(exp); return;
        }
        args.msg = {
            't': (_message.types.ENCRYPT+0),
            'i': (args.sender_id+''),
            'c': ct,
            'k': args.enc_symkey_args.slice(0)
        };
        cb(args.msg);
    };
    var args = {
        'cleartext': cleartext,
        'enc_symkey_args': enc_symkey_args,
        'sender_ks': sender_ks,
        'symkey_secret': symkey_secret,
        'sym_alg': sym_alg,
        'sym_opts': sym_opts
    };
    var tasks = [ 
            task_precheck_esk,
            task_check_args,
            task_encrypt_cleartext,
            task_get_sender_id,
            task_assemble_msg 
    ];
    var donef = function(msg){
        if(!_isExp(msg) && typeof msg==='object' && msg!==null){
            try{ msg = JSON.stringify(msg); }catch(e){}
        }
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};//function(enc_symkey_args_json, sender_ks, symkey_secret, sym_alg, sym_opts)

_message.sender.process.sign = 
function(cleartext, sender_ks, sender_ks_pass, callback, carry)
{
    var args = {
        'cleartext': cleartext,
        'sender_ks': sender_ks,
        'sender_ks_pass': sender_ks_pass
    };
    var task_check_args = function(cb, args){
        var runf = function(args){
            /* Validate cleartext */
            if(typeof args.cleartext!=='string' || args.cleartext.length<1){
                throw (new ncrypt.exception.types.simple.message.
                        message.invalidArgument());
            }
            /* Validate sender keyset */
            var ks;
            if(typeof args.sender_ks==='string'){
                if(typeof args.sender_ks_pass==='string' && 
                   args.sender_ks_pass.length>0){
                    ks = tkeyset.store.encrypt.decrypt(args.sender_ks, 
                                                       args.sender_ks_pass);
                    if(_isExp(ks)) return ks;
                }
            }else{ ks = args.sender_ks; }
            ks = new tkeyset.Keyset(ks);
            if(_isExp(ks)) return ks;
            args.sender_ks = ks;
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_sign_cleartext = function(cb, args){
        var runf = function(args){
            var ctxt = args.cleartext; // the text to sign
            var ks = args.sender_ks; // a 'Keyset' after validation
            var kp = ks.getKeypairSigning();
            var sig = new tsign.Signature(ctxt, kp);
            if(_isExp(sig)) return sig;
            args.signature = sig.getSignature();
            if(_isExp(args.signature)) return args.signature;
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_get_sender_id = function(cb, args){
        args.sender_id = args.sender_ks.getPublicKeyIDs().txt.normal+'';
        cb(args);
    };
    var task_assemble_msg = function(cb, args){
        args.msg = {
            't': _message.types.SIGN,
            'i': args.sender_id,
            'c': args.cleartext,
            's': args.signature
        };
        cb(args.msg);
    };
    var tasks = [
        task_check_args,
        task_sign_cleartext,
        task_get_sender_id,
        task_assemble_msg
    ];
    var donef = function(msg){
        if(!_isExp(msg) && typeof msg==='object' && msg!==null){
            try{ msg = JSON.stringify(msg); }catch(e){}
        }
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};
_message.sender.process.both = 
function(cleartext, enc_symkey_args, sender_ks, sender_ks_pass, 
         symkey_secret, sym_alg, sym_opts, callback, carry)
{
    var args = {
        'cleartext': cleartext,
        'enc_symkey_args': enc_symkey_args,
        'sender_ks': sender_ks,
        'sender_ks_pass': sender_ks_pass,
        'symkey_secret': symkey_secret,
        'sym_alg': sym_alg,
        'sym_opts': sym_opts
    };
    var task_encrypt_cleartext = function(cb, args){
        _message.sender.process.encrypt(
            args.cleartext, 
            args.enc_symkey_args, 
            args.sender_ks, 
            args.symkey_secret, 
            args.sym_alg, 
            args.sym_opts, 
            function(msg, c){
                if(_isExp(msg)){ cb(msg); return; }
                var args = c;
                args.msg_encrypted = msg;
                cb(args); return;
            }, 
            args
        );
    };
    var task_sign_ciphertext = function(cb, args){
        try{
            var m;
            if(typeof args.msg_encrypted === 'string'){
                m = JSON.parse(args.msg_encrypted);
            }else{ m = args.msg_encrypted; }
            var ctxt = m.c;
                ctxt = JSON.stringify(ctxt); // sign the ciphertext if the 
                                             // message is encrypted
        }catch(e){
            var exp = new SecureExec.exception.Exception(null,null,e);
            cb(exp); return;
        }
        _message.sender.process.sign(
            ctxt, 
            args.sender_ks, 
            args.sender_ks_pass, 
            function(msg, c){
                if(_isExp(msg)) return msg;
                var m_e;
                if(typeof args.msg_encrypted === 'string'){
                    m_e = JSON.parse(args.msg_encrypted);
                }else{ m_e = args.msg_encrypted; }
                if(typeof msg==='string'){
                    try{ msg = JSON.parse(msg); }catch(e){}
                }
                msg.k = m_e.k;
                msg.c = m_e.c;
                msg.t = _message.types.BOTH;
                msg = JSON.stringify(msg);
                cb(msg); return;
            }, 
            args
        );
    };
    var tasks = [
        task_encrypt_cleartext,
        task_sign_ciphertext
    ];
    var donef = function(msg){
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};

/**
 * @namespace nCrypt.asym.simple.message.sender
 * */
message.sender = {};
/**
 * @namespace nCrypt.asym.simple.message.sender.process
 * */
message.sender.process = {};

/**
 * Encrypt a message for one or more receivers.
 * @param {string} cleartext - Cleartext to encrypt. (Must be a *non-empty*
 * string.)
 * @param {object[]} enc_symkey_args - Array of objects. Either an array of 
 * arguments 
 * for {@link nCrypt.asym.types.simple.message.symkey.sender.arr.createEncryptedSymkeyArray},
 * an array resulting from this function, or a JSON object array like returned
 * from {@link nCrypt.asym.types.simple.message.symkey.sender.arr.symkeyArrayJSON}.
 * The most simple arguments array would be an array of objects 
 * like { 'public_keyset': receiver_public_keyset }, resulting in ECIES shared
 * secrets being calculated for each receiver.
 * @param {string} sender_ks - Sender keyset, i.e. your local keyset. (No 
 * password is required even if @sender_ks is encrypted, as only the public
 * key will be used to attach it's ID to the message.)
 * @param {string|nCrypt.asym.types.basic.secret.Secret} skey - `Secret` or 
 * serialized secret. The serialized value will be used to encrypt the actual 
 * message. Do not pass a password here, if using a password, create a `Secret` 
 * using the password as a string value.
 * @param {string} sym_alg - Symmetric algorithm to use for encryption.
 * @param {object} [sym_opts] - Symmetric encryption options, `null` or `{}` 
 * for defaults.
 * @param {function} callback - function([object|SecureExec.exception.exception]
 * msg, [*] carry). `msg` is a JSON string, stringify to send over the network.
 * @param {*} carry
 * @name encrypt
 * @function
 * @memberof nCrypt.asym.simple.message.sender.process
 * */
message.sender.process.encrypt = 
function(cleartext, enc_symkey_args, sender_ks, 
         symkey_secret, sym_alg, sym_opts, callback, carry)
{
    _message.sender.process.encrypt(cleartext, enc_symkey_args, sender_ks, 
         symkey_secret, sym_alg, sym_opts, callback, carry);
    return;
};

/**
 * Sign a message. (The message will NOT be encrypted, only signed.)
 * @param {string} cleartext
 * @param {string} sender_ks - Sender keyset, usually your local keyset. 
 * Private parts are required for signing.
 * @param {string} sender_ks_pass - If @sender_ks is encrypted, pass the 
 * password along. Otherwise, pass `null`.
 * @param {function} callback - function([object|SecureExec.exception.exception]
 * msg, [*] carry). `msg` is a JSON string, stringify to send over the network.
 * @param {*} carry
 * @name sign
 * @function
 * @memberof nCrypt.asym.simple.message.sender.process
 * */
message.sender.process.sign = 
function(cleartext, sender_ks, sender_ks_pass, callback, carry)
{
    _message.sender.process.sign(cleartext, sender_ks, sender_ks_pass, callback, carry);
    return;
};
/**
 * Encrypt and sign a message. (The signature will be created for the 
 * ciphertext, not for the cleartext.)
 * @param {string} cleartext - Cleartext to encrypt. (Must be a *non-empty*
 * string.)
 * @param {object[]} enc_symkey_args - Array of objects. Either an array of 
 * arguments 
 * for {@link nCrypt.asym.types.simple.message.symkey.sender.arr.createEncryptedSymkeyArray},
 * an array resulting from this function, or a JSON object array like returned
 * from {@link nCrypt.asym.types.simple.message.symkey.sender.arr.symkeyArrayJSON}.
 * The most simple arguments array would be an array of objects 
 * like { 'public_keyset': receiver_public_keyset }, resulting in ECIES shared
 * secrets being calculated for each receiver.
 * @param {string} sender_ks - Sender keyset, i.e. your local keyset. (Private
 * parts are required for signing.)
 * @param {string} sender_ks_pass - If @sender_ks is encrypted, pass the 
 * decryption password, otherwise pass `null`.
 * @param {string|nCrypt.asym.types.basic.secret.Secret} skey - Secret or 
 * serialized secret. The serialized value will be used to encrypt the actual 
 * message. Do not pass a password here, if using a password, create a `Secret` 
 * using the password as a string value.
 * @param {string} sym_alg - Symmetric algorithm to use for encryption.
 * @param {object} [sym_opts] - Symmetric encryption options, `null` or `{}` 
 * for defaults.
 * @param {function} callback - function([object|SecureExec.exception.exception]
 * msg, [*] carry). `msg` is a JSON string, stringify to send over the network.
 * @param {*} carry
 * @name both
 * @function
 * @memberof nCrypt.asym.simple.message.sender.process
 * */
message.sender.process.both = 
function(cleartext, enc_symkey_args, sender_ks, sender_ks_pass, 
         symkey_secret, sym_alg, sym_opts, callback, carry)
{
    _message.sender.process.both(cleartext, enc_symkey_args, 
                         sender_ks, sender_ks_pass, 
                         symkey_secret, sym_alg, sym_opts, 
                         callback, carry);
    return;
};

_message.receiver = {};
_message.receiver.info = {};
_message.receiver.info.getType = function(msg){
    var runf = function(){
        if(typeof msg==='string'){
            try{ msg = JSON.parse(msg); }
            catch(e){ msg = null; }
        }
        if(typeof msg!=='object' || msg===null || msg==={}){
            throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
        }
        var t = msg.t;
        if(typeof t!=='number' || _message.typesArray.indexOf(t)<0 ){
            throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
        }
        return t;
    };
    return SecureExec.sync.apply(runf, [msg]);
};
_message.receiver.info.getSenderID = function(msg){
    var runf = function(){
        if(typeof msg==='string'){
            try{ msg = JSON.parse(msg); }
            catch(e){ msg = null; }
        }
        if(typeof msg!=='object' || msg===null || msg==={}){
            throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
        }
        var i = msg.i;
        if(typeof i!=='string' || i.length<1 ){
            throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
        }
        return i;
    };
    return SecureExec.sync.apply(runf, [msg]);
};
_message.receiver.info.isEncrypted = function(msg){
    var t = _message.receiver.info.getType(msg);
    if(_isExp(t)) return t;
    if(t!==_message.types.SIGN){
        return true;
    }
    return false;
};
_message.receiver.info.getEncryptedSymkey = 
function(msg, local_keyset /*, local_keyset_pass*/ ){
    var runf = function(msg, local_keyset /*, local_keyset_pass*/){
        /* Get local keyset */
        /*var ks; var lks;
        if(typeof local_keyset==='string' && 
           typeof local_keyset_pass==='string'){
            lks = tkeyset.store.encrypt.decrypt(local_keyset, 
                                                local_keyset_pass);
            if(is_Exp(lks)) return lks;
        }else{ lks = local_keyset; }
        ks = new tkeyset.Keyset(lks);
        if(_isExp(ks)) return ks;*/
        
        /* Get encrypted symkey array */
        var t = _message.receiver.info.getType(msg);
        if(_isExp(t)) return t;
        if(t===_message.types.SIGN){
            throw (new ncrypt.exception.types.simple.message.message.
                messageIsNotEncrypted());
        }
        if(typeof msg==='string'){
            try{ msg = JSON.parse(msg); }
            catch(e){
                throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
            }
        }
        var sks = msg.k;
        if(typeof sks!=='object' || !Array.isArray(sks)){
            throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
        }
        
        /* Get the symmetric key object for own keyset */
        var esk = tsymkey.receiver.arr.extractItem(sks, local_keyset);
        return esk;
    };
    return SecureExec.sync.apply(runf, 
        [msg, local_keyset/*, local_keyset_pass*/]);
};

/**
 * @namespace nCrypt.asym.simple.message.receiver
 * */
message.receiver = {};
/**
 * @namespace nCrypt.asym.simple.message.receiver.info
 * */
message.receiver.info = {};

/**
 * Get the message type, which is an integer, representing encrypted, signed,
 * or both.
 * @returns {number|SecureExec.exception.exception}
 * @function
 * @name getType
 * @memberof nCrypt.asym.simple.message.receiver.info
 * */
message.receiver.info.getType = function(msg){
    return _message.receiver.info.getType(msg);
};
/**
 * Return the sender keyset's ID. The ID is a text ID of normal length, i.e.
 * retrieved using (keyset).getPublicKeyIDs.txt.normal.
 * @returns {string|SecureExec.exception.exception}
 * @function
 * @name getSenderID
 * @memberof nCrypt.asym.simple.message.receiver.info
 * */
message.receiver.info.getSenderID = function(msg){
    return _message.receiver.info.getSenderID(msg);
};
/**
 * Check whether a message is encrypted.
 * @param {string} msg
 * @returns {boolean|SecureExec.exception.exception}
 * @name isEncrypted 
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.info
 * */
message.receiver.info.isEncrypted = function(msg){
    return _message.receiver.info.isEncrypted(msg);
};
/**
 * From an encrypted message, get the encrypted symmetric key object (JSON
 * object) for a certain keyset. If the message wasn't encrypted for this 
 * keyset, `null` is returned.
 * @param {string} msg
 * @param {string} local_keyset
 * @returns {object|SecureExec.exception.exception}
 * @name getEncryptedSymkey
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.info
 * */
message.receiver.info.getEncryptedSymkey = function(msg, local_keyset){
    return _message.receiver.info.getEncryptedSymkey(msg, local_keyset);
};

_message.receiver.process = {};
_message.receiver.process.decrypt = 
function(
    msg, 
    local_keyset, local_keyset_pass, 
    sender_ks, shared_secret, 
    callback, carry)
{
    var args = {
        'msg': msg,
        'local_keyset': local_keyset,
        'local_keyset_pass': local_keyset_pass,
        'sender_ks': sender_ks,
        'shared_secret': shared_secret
    };
    var task_check_args = function(cb, args){
        var runf = function(args){
            /* Check args.msg */
            var t = _message.receiver.info.getType(msg);
            if(_isExp(t)) return t;
            if(t===_message.types.SIGN){
                throw (new ncrypt.exception.types.simple.message.message.
                    messageIsNotEncrypted());
            }
            if(typeof args.msg==='string'){
                try{
                    args.msg = JSON.parse(args.msg);
                }catch(e){
                    throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
                }
            }
            /* Check args.local_keyset */
            if(typeof args.local_keyset==='string' &&
               typeof args.local_keyset_pass==='string'){
                   args.local_keyset = 
                    tkeyset.store.encrypt.decrypt(args.local_keyset,
                                                  args.local_keyset_pass);
            }
            args.lks = new tkeyset.Keyset(args.local_keyset);
            if(_isExp(args.lks)) return args.lks;
            /* Check args.sender_ks */
            if(typeof args.sender_ks!=='undefined' &&
               !(typeof args.sender_ks==='object' && args.sender_ks===null)){
                if(typeof args.sender_ks==='string'){
                    args.sender_ks = tkeyset.pub.getPublicKeyset(
                        args.sender_ks);
                }
                args.sks = new tkeyset.Keyset(args.sender_ks);
                if(_isExp(args.sks)) return args.sks;
            }else{ args.sks = null; }
            /* Check args.shared_secret */
            if(typeof args.shared_secret!=='undefined' &&
               !(typeof args.shared_secret==='object' && 
                 args.shared_secret===null)){
                if(typeof args.shared_secret!=='object'){
                    throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
                }
                if(args.shared_secret instanceof tsecret.Secret ||
                   args.shared_secret instanceof tdh.SecretDH ||
                   args.shared_secret instanceof tecies.SecretECIES){
                    args.shared_secret = args.shared_secret.getSecretValue();
                }else{
                    throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
                }
                if(typeof args.shared_secret!=='string'){
                    throw (new ncrypt.exception.types.simple.message.message.
                        invalidArgument());
                }
                args.shared_secret = new tsecret.Secret(tsecret.source.SECRET,
                                        args.shared_secret);
                if(_isExp(args.shared_secret)) return args.shared_secret;
                args.shared_secret = args.shared_secret.getSecretValue();
            }else{ args.shared_secret=null; }
            return args;
        };
        // args.lks (instance of 'Keyset'), args.sks (instance of 'Keyset'),
        // args.shared_secret (serialized 'Secret', string)
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_get_encrypted_symkey = function(cb, args){
        var runf = function(args){
            var ks = args.lks.getSerialized();
            args.encsk = 
                _message.receiver.info.getEncryptedSymkey(args.msg, ks);
            if(_isExp(args.encsk)){ return args.encsk; }
            if(typeof args.encsk==='object' && args.encsk===null) return null;
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_restore_shared_secret = function(cb, args){
        var runf = function(args){
            if(typeof args.shared_secret === 'string'){
                return args;
            }
            var stype; try{ stype = args.encsk.t; }catch(e){ stype = null; }
            if(typeof stype!=='string'){
                throw (new ncrypt.exception.types.simple.message.message.
                malformedMessage());
            }
            if(stype === 'dh'){
                if(args.sks === null){
                    throw (new ncrypt.exception.types.simple.message.
                        message.missingSenderKeyset());
                }
                if(!args.sks.hasEncryptionKeypair() || 
                   !args.lks.hasEncryptionKeypair()){
                    throw (new ncrypt.exception.types.simple.message.
                        message.missingEncryptionKeypair());
                }
                var kp_loc = args.lks.getKeypairEncryption();
                var kp_pub = args.sks.getKeypairEncryption();
                args.shared_secret = new tdh.SecretDH(kp_loc, kp_pub);
            }else if(stype === 'ecies'){
                var tag; try{ tag = args.encsk.tag; }catch(e){ tag = null; }
                if(typeof tag!=='object'){
                    throw (new ncrypt.exception.types.simple.message.
                        message.malformedMessage());
                }
                try{
                    tag = JSON.stringify(tag);
                }catch(e){
                    throw (new ncrypt.exception.types.simple.message.
                        message.malformedMessage());
                }
                var kp = args.lks.getKeypairEncryption();
                if(kp===null){ 
                    throw (new ncrypt.exception.types.simple.message.
                        message.missingEncryptionKeypair());
                }
                args.shared_secret = new tecies.SecretECIES(kp, tag);
            }else{
                throw (new ncrypt.exception.types.simple.message.message.
                malformedMessage());
            }
            if(_isExp(args.shared_secret)) return args.shared_secret;
            args.shared_secret = args.shared_secret.getSecretValue();
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_decrypt_symkey = function(cb, args){
        var runf = function(args){
            var esk = args.encsk;
            var sec = args.shared_secret;
            var skey = new tsymkey.receiver.EncSymkeyReceiver(esk, sec);
            if(_isExp(skey)) return skey;
            var sym_key = skey.getDecryptedSymkey();
            if(typeof sym_key!=='string' || sym_key.length<1){
                throw (new nCrypt.exception.types.simple.message.message.
                    cannotDecryptSymkey());
            }
            args.skey = sym_key+'';
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_decrypt_message = function(cb, args){
        var ciphertext = args.msg.c;
        if(typeof ciphertext === 'object'){
            try{
                ciphertext = JSON.stringify(ciphertext);
            }catch(e){
                throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
            }
        }
        ncrypt.sym.async.decrypt(ciphertext, args.skey, function(res, c){
            var args = c.a; var cb = c.c;
            if(_isExp(res)){ cb(res); return; }
            cb(res); return; 
        }, { 'a': args, 'c': cb });
    };
    var tasks = [
        task_check_args,
        task_get_encrypted_symkey,
        task_restore_shared_secret,
        task_decrypt_symkey,
        task_decrypt_message
    ];
    var donef = function(msg){
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                if(typeof res==='object' && res===null){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};
_message.receiver.process.verify = 
function(msg, sender_ks, callback, carry)
{
    var args = {
        'msg': msg,
        'sender_ks': sender_ks
    };
    var task_check_args = function(cb, args){
        var runf = function(args){
            /* Check args.msg */
            var t = _message.receiver.info.getType(msg);
            if(_isExp(t)) return t;
            if(t===_message.types.ENCRYPT){
                throw (new ncrypt.exception.types.simple.message.message.
                    messageIsNotSigned());
            }
            if(typeof args.msg==='string'){
                try{
                    args.msg = JSON.parse(args.msg);
                }catch(e){
                    throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
                }
            }
            /* Check args.sender_ks */
            if(typeof args.sender_ks==='string'){
                args.sender_ks = tkeyset.pub.getPublicKeyset(
                    args.sender_ks);
            }
            args.sks = new tkeyset.Keyset(args.sender_ks);
            if(_isExp(args.sks)) return args.sks;
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_check_cleartext = function(cb, args){
        var runf = function(args){
            args.cleartext = args.msg.c;
            if(typeof args.cleartext==='object'){
                try{
                    args.cleartext = JSON.stringify(args.cleartext)+'';
                }catch(e){
                    throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
                }
            }
            if(typeof args.cleartext!=='string' || args.cleartext.length<1){
                throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
            }
            return args;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var task_verify = function(cb, args){
        var runf = function(args){
            var sks = args.sks;
            var ctxt = args.cleartext;
            var sig = args.msg.s;
            if(typeof sig!=='string' || sig.length<1){
                throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
            }
            if(!sks.hasSigningKeypair()){
                throw (new nCrypt.exception.types.simple.message.
                        message.missingSigningKeypair());
            }
            var kp = sks.getKeypairSigning();
            var s = new tsign.Signature(ctxt, kp, sig);
            if(_isExp(s)) return s;
            args.verified = s.getVerified();
            return args.verified;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var tasks = [
        task_check_args,
        task_check_cleartext,
        task_verify
    ];
    var donef = function(msg){
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};
_message.receiver.process.both = 
function(
    msg, 
    local_keyset, local_keyset_pass, 
    sender_ks, shared_secret, 
    callback, carry)
{
    var args_decrypt = {
        'msg': msg,
        'local_keyset': local_keyset,
        'local_keyset_pass': local_keyset_pass,
        'sender_ks': sender_ks,
        'shared_secret': shared_secret
    };
    var args_verify = {
        'msg': msg,
        'sender_ks': sender_ks
    };
    try{
        if(typeof args_verify.msg==='object'){
            args_verify.msg=JSON.stringify(args_verify.msg)+'';
        }
        if(typeof args.sender_ks==='object'){
            if(args.sender_ks instanceof tkeyset.Keyset){
                args.sender_ks = args.sender_ks.getPublicKeyset()+'';
            }
        }}
    catch(e){}
    var args = { 'decrypt': args_decrypt, 'verify': args_verify, 'res': {} };
    var task_decrypt = function(cb, args){
        _message.receiver.process.decrypt(
            args.decrypt.msg,
            args.decrypt.local_keyset,
            args.decrypt.local_keyset_pass,
            args.decrypt.sender_ks,
            args.decrypt.shared_secret,
            function(res, c){
                var args = c.a; var cb = c.c;
                if(_isExp(res)){ cb(res); return; }
                args.res.cleartext = res;
                cb(args); return;
            },
            { 'a': args, 'c': cb }
        );
    };
    var task_verify = function(cb, args){
        _message.receiver.process.verify(
            args.verify.msg,
            args.verify.sender_ks,
            function(ver, c){
                var args = c.a; var cb = c.c;
                //if(_isExp(ver)){ cb(ver); return; }
                args.res.verified = ver;
                cb(args); return;
            },
            { 'a': args, 'c': cb }
        );
    };
    var task_result = function(cb, args){
        var runf = function(args){
            var res = {};
            res.cleartext = args.res.cleartext;
            res.verified = args.res.verified;
            return res;
        };
        args = SecureExec.sync.apply(runf, [ args ]);
        cb(args);
    };
    var tasks = [ task_decrypt, task_verify, task_result ];
    var donef = function(msg){
        callback(msg, carry);
    };
    var iterate_tasks = function(tasks, args){
        if(tasks.length<1){ donef(args); return; }
        var t = tasks.shift();
        setTimeout(function(){
            t(function(res){
                if(_isExp(res)){ donef(res); return; }
                iterate_tasks(tasks.slice(0), res); return;
            }, args);
        }, 0);
    };
    iterate_tasks(tasks.slice(0), args);
};

_message.receiver.process.knownKey = {};
_message.receiver.process.knownKey.decrypt = 
function(msg, skey, callback, carry){
    var get_ciphertext = function(msg){
        var t = _message.receiver.info.getType(msg);
        if(_isExp(t)) return t;
        if(t===_message.types.SIGN){
            throw (new ncrypt.exception.types.simple.message.message.
                messageIsNotEncrypted());
        }
        if(typeof msg==='string'){
            try{ msg = JSON.parse(msg); }catch(e){ msg = null; }
            if(typeof msg==='undefined' || msg===null){
                throw (new ncrypt.exception.types.simple.message.message.
                    malformedMessage());
            }
        }
        var ciphertext = msg.c;
        if(typeof ciphertext!=='object'){
            throw (new ncrypt.exception.types.simple.message.message.
                malformedMessage());
        }
        try{
            ciphertext = JSON.stringify(ciphertext);
        }catch(e){
            throw (new ncrypt.exception.types.simple.message.message.
                malformedMessage());
        }
        return ciphertext;
    };
    var get_skey = function(skey){
        if(typeof skey!=='string'){
            if(typeof skey!=='object' || skey===null ||
               typeof skey.getSecretValue!=='function'){
                throw (new ncrypt.exception.types.simple.message.
                        message.invalidArgument());
            }
            skey = skey.getSecretValue();
        }
        return skey;
    };
    var _ciphertext = SecureExec.sync.apply(get_ciphertext, [ msg ]);
    if(_isExp(_ciphertext)) return _ciphertext;
    var _skey = SecureExec.sync.apply(get_skey, [ skey ]);
    if(_isExp(_skey)) return _skey;
    ncrypt.sym.async.decrypt(_ciphertext, _skey, function(dec, c){
        c.c(dec, c.ca); return;
    }, { 'c': callback, 'ca': carry });
};
_message.receiver.process.knownKey.both = 
function(msg, skey, sender_ks, callback, carry)
{
    var args = {
        'msg': msg, 'skey': skey, 'sender_ks': sender_ks,
        'cb': callback, 'ca': carry
    };
    _message.receiver.process.knownKey.decrypt(args.msg, args.skey,
    function(dec,c){
        args.res = {}; args.res.cleartext = dec;
        _message.receiver.process.verify(args.msg, args.sender_ks,
        function(ver, c){
            var res = {};
            res.cleartext = args.res.cleartext;
            res.verified = ver;
            args.cb(res, args.ca);
        }, args);
    }, args);
};

/**
 * @namespace nCrypt.asym.simple.message.receiver.process
 * */
message.receiver.process = {};

/**
 * Decrypt an encrypted message.
 * @param {string} msg - Message to decrypt.
 * @param {string} local_keyset - Local keyset, private information is required.
 * @param {string} local_keyset_pass - If @local_keyset is encrypted, pass 
 * the decryption password here, otherwise `null`.
 * @param {string} sender_ks - Pass the sender's (public) keyset here. If not
 * available, pass `null`. The @sender_ks is required if a shared secret of a
 * DH type needs to be recovered.
 * @param {string|nCrypt.asym.types.basic.secret.Secret|nCrypt.asym.types.shared.dh.SecretDH|nCrypt.asym.types.shared.ecies.SecretECIES} shared_secret - Known 
 * shared secret (will be derived from sender keyset and local keyset if 
 * none passed).
 * @param {function} - function([string|SecureExec.exception.Exception] 
 * cleartext, [*] carry)
 * @param {*} carry
 * @name decrypt
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.process
 * */
message.receiver.process.decrypt = 
function(
    msg, 
    local_keyset, local_keyset_pass, 
    sender_ks, shared_secret, 
    callback, carry)
{
    _message.receiver.process.decrypt(
        msg, 
        local_keyset, local_keyset_pass, 
        sender_ks, shared_secret, 
        callback, carry
    );
};

/**
 * Verify a signature's message.
 * @param {string} msg - Message to verify signature of.
 * @param {string} sender_ks - Sender's (public) keyset.
 * @param {function} - function([boolean] verified, [*] carry)
 * @param {*} carry
 * @name verify
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.process
 * */
message.receiver.process.verify = 
function(msg, sender_ks, callback, carry)
{
    _message.receiver.process.verify(msg, sender_ks, callback, carry);
};

/**
 * Decrypt an encrypted message and verify it's signature.
 * @param {string} msg - Message to decrypt.
 * @param {string} local_keyset - Local keyset, private information is required.
 * @param {string} local_keyset_pass - If @local_keyset is encrypted, pass 
 * the decryption password here, otherwise `null`.
 * @param {string} sender_ks - Sender's (public) keyset. (Required
 * for signature verification.)
 * @param {string|nCrypt.asym.types.basic.secret.Secret|nCrypt.asym.types.shared.dh.SecretDH|nCrypt.asym.types.shared.ecies.SecretECIES} shared_secret - Known 
 * shared secret (will be derived from sender keyset and local keyset if not passed).
 * @param {function} - function([string|SecureExec.exception.Exception] 
 * obj, [*] carry), with `obj` being an object like { 'cleartext': [string] 
 * cleartext, 'verified': [boolean] verified }.
 * @param {*} carry
 * @name both
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.process
 * */
message.receiver.process.both = 
function(
    msg, 
    local_keyset, local_keyset_pass, 
    sender_ks, shared_secret, 
    callback, carry)
{
    _message.receiver.process.both(
        msg, 
        local_keyset, local_keyset_pass, 
        sender_ks, shared_secret, 
        callback, carry
    );
};

/**
 * @namespace nCrypt.asym.simple.message.receiver.process.knownKey
 * */
message.receiver.process.knownKey = {};
/**
 * Decrypt a message when the symmetric key is known.
 * @param {string} msg - Message to decrypt. (The message, not the ciphertext
 * only.)
 * @param {string|nCrypt.asym.types.basic.secret.Secret} skey - Known symmetric 
 * key. If passing a string, it is treated as a serialized `Secret`. If you 
 * have a password etc., (i.e. not a serialized `Secret`), create secret (in
 * case of a password, from a string source), before passing it.
 * @param {function} callback - function([string|SecureExec.exception.Exception]
 * cleartext, [*] carry)
 * @param {*} carry
 * @name decrypt
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.process.knownKey
 * */
message.receiver.process.knownKey.decrypt = 
function(msg, skey, callback, carry)
{
    _message.receiver.process.knownKey.decrypt(msg, skey, callback, carry);
};
/**
 * Decrypt and verify message when the symmetric key is known.
 * @param {string} msg - Message to decrypt and verify. 
 * @param {string|nCrypt.asym.types.basic.secret.Secret} skey - Known symmetric 
 * key. If passing a string, it is treated as a serialized `Secret`. If you 
 * have a password etc., (i.e. not a serialized `Secret`), create secret (in
 * case of a password, from a string source), before passing it.
 * @param {string} sender_ks - Sender's keyset to verify the signature.
 * @param {function} - function([string|SecureExec.exception.Exception] 
 * obj, [*] carry), with `obj` being an object like { 'cleartext': [string] 
 * cleartext, 'verified': [boolean] verified }.
 * @param {*} carry
 * @name decrypt
 * @function
 * @memberof nCrypt.asym.simple.message.receiver.process.knownKey
 * */
message.receiver.process.knownKey.both = 
function(msg, skey, sender_ks, callback, carry)
{
    _message.receiver.process.knownKey.both(
        msg, skey, sender_ks, callback, carry);
};

return message });
