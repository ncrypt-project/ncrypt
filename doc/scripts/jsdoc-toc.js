(function($) {
    // TODO: make the node ID configurable
    var treeNode = $('#jsdoc-toc-nav');

    // initialize the tree
    treeNode.tree({
        autoEscape: false,
        closedIcon: '&#x21e2;',
        data: [{"label":"<a href=\"nCrypt.html\">nCrypt</a>","id":"nCrypt","children":[{"label":"<a href=\"nCrypt.asym.html\">asym</a>","id":"nCrypt.asym","children":[{"label":"<a href=\"nCrypt.asym.simple.html\">simple</a>","id":"nCrypt.asym.simple","children":[{"label":"<a href=\"nCrypt.asym.simple.keyset.html\">keyset</a>","id":"nCrypt.asym.simple.keyset","children":[{"label":"<a href=\"nCrypt.asym.simple.keyset.gen.html\">gen</a>","id":"nCrypt.asym.simple.keyset.gen","children":[]},{"label":"<a href=\"nCrypt.asym.simple.keyset.priv.html\">priv</a>","id":"nCrypt.asym.simple.keyset.priv","children":[]},{"label":"<a href=\"nCrypt.asym.simple.keyset.pub.html\">pub</a>","id":"nCrypt.asym.simple.keyset.pub","children":[]}]},{"label":"<a href=\"nCrypt.asym.simple.message.html\">message</a>","id":"nCrypt.asym.simple.message","children":[{"label":"<a href=\"nCrypt.asym.simple.message.receiver.html\">receiver</a>","id":"nCrypt.asym.simple.message.receiver","children":[{"label":"<a href=\"nCrypt.asym.simple.message.receiver.info.html\">info</a>","id":"nCrypt.asym.simple.message.receiver.info","children":[]},{"label":"<a href=\"nCrypt.asym.simple.message.receiver.process.html\">process</a>","id":"nCrypt.asym.simple.message.receiver.process","children":[{"label":"<a href=\"nCrypt.asym.simple.message.receiver.process.knownKey.html\">knownKey</a>","id":"nCrypt.asym.simple.message.receiver.process.knownKey","children":[]}]}]},{"label":"<a href=\"nCrypt.asym.simple.message.sender.html\">sender</a>","id":"nCrypt.asym.simple.message.sender","children":[{"label":"<a href=\"nCrypt.asym.simple.message.sender.process.html\">process</a>","id":"nCrypt.asym.simple.message.sender.process","children":[]}]},{"label":"<a href=\"nCrypt.asym.simple.message.types.html\">types</a>","id":"nCrypt.asym.simple.message.types","children":[]}]},{"label":"<a href=\"nCrypt.asym.simple.secret.html\">secret</a>","id":"nCrypt.asym.simple.secret","children":[{"label":"<a href=\"nCrypt.asym.simple.secret.dh.html\">dh</a>","id":"nCrypt.asym.simple.secret.dh","children":[]},{"label":"<a href=\"nCrypt.asym.simple.secret.ecies.html\">ecies</a>","id":"nCrypt.asym.simple.secret.ecies","children":[]}]},{"label":"<a href=\"nCrypt.asym.simple.signature.html\">signature</a>","id":"nCrypt.asym.simple.signature","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.html\">types</a>","id":"nCrypt.asym.types","children":[{"label":"<a href=\"nCrypt.asym.types.basic.html\">basic</a>","id":"nCrypt.asym.types.basic","children":[{"label":"<a href=\"nCrypt.asym.types.basic.bn.html\">bn</a>","id":"nCrypt.asym.types.basic.bn","children":[{"label":"<a href=\"nCrypt.asym.types.basic.bn.BigNumber.html\">BigNumber</a>","id":"nCrypt.asym.types.basic.bn.BigNumber","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.basic.id.html\">id</a>","id":"nCrypt.asym.types.basic.id","children":[{"label":"<a href=\"nCrypt.asym.types.basic.id.ID.html\">ID</a>","id":"nCrypt.asym.types.basic.id.ID","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.basic.point.html\">point</a>","id":"nCrypt.asym.types.basic.point","children":[{"label":"<a href=\"nCrypt.asym.types.basic.point.Point.html\">Point</a>","id":"nCrypt.asym.types.basic.point.Point","children":[]},{"label":"<a href=\"nCrypt.asym.types.basic.point.cache.html\">cache</a>","id":"nCrypt.asym.types.basic.point.cache","children":[]},{"label":"<a href=\"nCrypt.asym.types.basic.point.curves.html\">curves</a>","id":"nCrypt.asym.types.basic.point.curves","children":[{"label":"<a href=\"nCrypt.asym.types.basic.point.curves.available.html\">available</a>","id":"nCrypt.asym.types.basic.point.curves.available","children":[]},{"label":"<a href=\"nCrypt.asym.types.basic.point.curves.validate.html\">validate</a>","id":"nCrypt.asym.types.basic.point.curves.validate","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.basic.point.ec.html\">ec</a>","id":"nCrypt.asym.types.basic.point.ec","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.basic.secret.html\">secret</a>","id":"nCrypt.asym.types.basic.secret","children":[{"label":"<a href=\"nCrypt.asym.types.basic.secret.Secret.html\">Secret</a>","id":"nCrypt.asym.types.basic.secret.Secret","children":[]}]}]},{"label":"<a href=\"nCrypt.asym.types.key.html\">key</a>","id":"nCrypt.asym.types.key","children":[{"label":"<a href=\"nCrypt.asym.types.key.keypair.html\">keypair</a>","id":"nCrypt.asym.types.key.keypair","children":[{"label":"<a href=\"nCrypt.asym.types.key.keypair.Keypair.html\">Keypair</a>","id":"nCrypt.asym.types.key.keypair.Keypair","children":[]},{"label":"<a href=\"nCrypt.asym.types.key.keypair.store.html\">store</a>","id":"nCrypt.asym.types.key.keypair.store","children":[{"label":"<a href=\"nCrypt.asym.types.key.keypair.store.encrypt.html\">encrypt</a>","id":"nCrypt.asym.types.key.keypair.store.encrypt","children":[]}]}]}]},{"label":"<a href=\"nCrypt.asym.types.shared.html\">shared</a>","id":"nCrypt.asym.types.shared","children":[{"label":"<a href=\"nCrypt.asym.types.shared.dh.html\">dh</a>","id":"nCrypt.asym.types.shared.dh","children":[{"label":"<a href=\"nCrypt.asym.types.shared.dh.SecretDH.html\">SecretDH</a>","id":"nCrypt.asym.types.shared.dh.SecretDH","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.shared.ecies.html\">ecies</a>","id":"nCrypt.asym.types.shared.ecies","children":[{"label":"<a href=\"nCrypt.asym.types.shared.ecies.SecretECIES.html\">SecretECIES</a>","id":"nCrypt.asym.types.shared.ecies.SecretECIES","children":[]}]}]},{"label":"<a href=\"nCrypt.asym.types.signature.html\">signature</a>","id":"nCrypt.asym.types.signature","children":[{"label":"<a href=\"nCrypt.asym.types.signature.ecdsa.html\">ecdsa</a>","id":"nCrypt.asym.types.signature.ecdsa","children":[{"label":"<a href=\"nCrypt.asym.types.signature.ecdsa.Signature.html\">Signature</a>","id":"nCrypt.asym.types.signature.ecdsa.Signature","children":[]}]}]},{"label":"<a href=\"nCrypt.asym.types.simple.html\">simple</a>","id":"nCrypt.asym.types.simple","children":[{"label":"<a href=\"nCrypt.asym.types.simple.keyset.html\">keyset</a>","id":"nCrypt.asym.types.simple.keyset","children":[{"label":"<a href=\"nCrypt.asym.types.simple.keyset.Keyset.html\">Keyset</a>","id":"nCrypt.asym.types.simple.keyset.Keyset","children":[]},{"label":"<a href=\"nCrypt.asym.types.simple.keyset.pub.html\">pub</a>","id":"nCrypt.asym.types.simple.keyset.pub","children":[]},{"label":"<a href=\"nCrypt.asym.types.simple.keyset.store.html\">store</a>","id":"nCrypt.asym.types.simple.keyset.store","children":[{"label":"<a href=\"nCrypt.asym.types.simple.keyset.store.encrypt.html\">encrypt</a>","id":"nCrypt.asym.types.simple.keyset.store.encrypt","children":[]}]}]},{"label":"<a href=\"nCrypt.asym.types.simple.message.html\">message</a>","id":"nCrypt.asym.types.simple.message","children":[{"label":"<a href=\"nCrypt.asym.types.simple.message.message.html\">message</a>","id":"nCrypt.asym.types.simple.message.message","children":[{"label":"<a href=\"nCrypt.asym.types.simple.message.message.sender.html\">sender</a>","id":"nCrypt.asym.types.simple.message.message.sender","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.html\">symkey</a>","id":"nCrypt.asym.types.simple.message.symkey","children":[{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.receiver.html\">receiver</a>","id":"nCrypt.asym.types.simple.message.symkey.receiver","children":[{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.receiver.EncSymkeyReceiver.html\">EncSymkeyReceiver</a>","id":"nCrypt.asym.types.simple.message.symkey.receiver.EncSymkeyReceiver","children":[]},{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.receiver.arr.html\">arr</a>","id":"nCrypt.asym.types.simple.message.symkey.receiver.arr","children":[]}]},{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.sender.html\">sender</a>","id":"nCrypt.asym.types.simple.message.symkey.sender","children":[{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.sender.EncSymkeySender.html\">EncSymkeySender</a>","id":"nCrypt.asym.types.simple.message.symkey.sender.EncSymkeySender","children":[]},{"label":"<a href=\"nCrypt.asym.types.simple.message.symkey.sender.arr.html\">arr</a>","id":"nCrypt.asym.types.simple.message.symkey.sender.arr","children":[]}]}]}]}]}]}]},{"label":"<a href=\"nCrypt.enc.html\">enc</a>","id":"nCrypt.enc","children":[]},{"label":"<a href=\"nCrypt.exception.html\">exception</a>","id":"nCrypt.exception","children":[{"label":"<a href=\"nCrypt.exception.asym.html\">asym</a>","id":"nCrypt.exception.asym","children":[{"label":"<a href=\"nCrypt.exception.asym.simple.html\">simple</a>","id":"nCrypt.exception.asym.simple","children":[{"label":"<a href=\"nCrypt.exception.asym.simple.secret.html\">secret</a>","id":"nCrypt.exception.asym.simple.secret","children":[]},{"label":"<a href=\"nCrypt.exception.asym.simple.signature.html\">signature</a>","id":"nCrypt.exception.asym.simple.signature","children":[]}]}]},{"label":"<a href=\"nCrypt.exception.enc.html\">enc</a>","id":"nCrypt.exception.enc","children":[]},{"label":"<a href=\"nCrypt.exception.global.html\">global</a>","id":"nCrypt.exception.global","children":[]},{"label":"<a href=\"nCrypt.exception.hash.html\">hash</a>","id":"nCrypt.exception.hash","children":[]},{"label":"<a href=\"nCrypt.exception.init.html\">init</a>","id":"nCrypt.exception.init","children":[]},{"label":"<a href=\"nCrypt.exception.sym.html\">sym</a>","id":"nCrypt.exception.sym","children":[]},{"label":"<a href=\"nCrypt.exception.types.html\">types</a>","id":"nCrypt.exception.types","children":[{"label":"<a href=\"nCrypt.exception.types.basic.html\">basic</a>","id":"nCrypt.exception.types.basic","children":[{"label":"<a href=\"nCrypt.exception.types.basic.bn.html\">bn</a>","id":"nCrypt.exception.types.basic.bn","children":[]},{"label":"<a href=\"nCrypt.exception.types.basic.id.html\">id</a>","id":"nCrypt.exception.types.basic.id","children":[]},{"label":"<a href=\"nCrypt.exception.types.basic.point.html\">point</a>","id":"nCrypt.exception.types.basic.point","children":[]},{"label":"<a href=\"nCrypt.exception.types.basic.secret.html\">secret</a>","id":"nCrypt.exception.types.basic.secret","children":[]}]},{"label":"<a href=\"nCrypt.exception.types.key.html\">key</a>","id":"nCrypt.exception.types.key","children":[{"label":"<a href=\"nCrypt.exception.types.key.keypair.html\">keypair</a>","id":"nCrypt.exception.types.key.keypair","children":[]}]},{"label":"<a href=\"nCrypt.exception.types.shared.html\">shared</a>","id":"nCrypt.exception.types.shared","children":[{"label":"<a href=\"nCrypt.exception.types.shared.dh.html\">dh</a>","id":"nCrypt.exception.types.shared.dh","children":[]},{"label":"<a href=\"nCrypt.exception.types.shared.ecies.html\">ecies</a>","id":"nCrypt.exception.types.shared.ecies","children":[]}]},{"label":"<a href=\"nCrypt.exception.types.signature.html\">signature</a>","id":"nCrypt.exception.types.signature","children":[{"label":"<a href=\"nCrypt.exception.types.signature.ecdsa.html\">ecdsa</a>","id":"nCrypt.exception.types.signature.ecdsa","children":[]}]},{"label":"<a href=\"nCrypt.exception.types.simple.html\">simple</a>","id":"nCrypt.exception.types.simple","children":[{"label":"<a href=\"nCrypt.exception.types.simple.keyset.html\">keyset</a>","id":"nCrypt.exception.types.simple.keyset","children":[]},{"label":"<a href=\"nCrypt.exception.types.simple.message.html\">message</a>","id":"nCrypt.exception.types.simple.message","children":[{"label":"<a href=\"nCrypt.exception.types.simple.message.message.html\">message</a>","id":"nCrypt.exception.types.simple.message.message","children":[]},{"label":"<a href=\"nCrypt.exception.types.simple.message.symkey.html\">symkey</a>","id":"nCrypt.exception.types.simple.message.symkey","children":[]}]}]}]}]},{"label":"<a href=\"nCrypt.hash.html\">hash</a>","id":"nCrypt.hash","children":[]},{"label":"<a href=\"nCrypt.init.html\">init</a>","id":"nCrypt.init","children":[]},{"label":"<a href=\"nCrypt.random.html\">random</a>","id":"nCrypt.random","children":[{"label":"<a href=\"nCrypt.random.crypto.html\">crypto</a>","id":"nCrypt.random.crypto","children":[{"label":"<a href=\"nCrypt.random.crypto.int32.html\">int32</a>","id":"nCrypt.random.crypto.int32","children":[]},{"label":"<a href=\"nCrypt.random.crypto.int8.html\">int8</a>","id":"nCrypt.random.crypto.int8","children":[]}]},{"label":"<a href=\"nCrypt.random.number.html\">number</a>","id":"nCrypt.random.number","children":[]},{"label":"<a href=\"nCrypt.random.str.html\">str</a>","id":"nCrypt.random.str","children":[]}]},{"label":"<a href=\"nCrypt.sym.html\">sym</a>","id":"nCrypt.sym","children":[{"label":"<a href=\"nCrypt.sym.async.html\">async</a>","id":"nCrypt.sym.async","children":[]},{"label":"<a href=\"nCrypt.sym.config.html\">config</a>","id":"nCrypt.sym.config","children":[{"label":"<a href=\"nCrypt.sym.config.blockcipher.html\">blockcipher</a>","id":"nCrypt.sym.config.blockcipher","children":[{"label":"<a href=\"nCrypt.sym.config.blockcipher.aes.html\">aes</a>","id":"nCrypt.sym.config.blockcipher.aes","children":[]}]}]},{"label":"<a href=\"nCrypt.sym.sync.html\">sync</a>","id":"nCrypt.sym.sync","children":[]}]},{"label":"<a href=\"nCrypt.tools.html\">tools</a>","id":"nCrypt.tools","children":[{"label":"<a href=\"nCrypt.tools.proto.html\">proto</a>","id":"nCrypt.tools.proto","children":[{"label":"<a href=\"nCrypt.tools.proto.arr.html\">arr</a>","id":"nCrypt.tools.proto.arr","children":[]},{"label":"<a href=\"nCrypt.tools.proto.jsonobj.html\">jsonobj</a>","id":"nCrypt.tools.proto.jsonobj","children":[]},{"label":"<a href=\"nCrypt.tools.proto.str.html\">str</a>","id":"nCrypt.tools.proto.str","children":[]}]}]}]}],
        openedIcon: ' &#x21e3;',
        saveState: true,
        useContextMenu: false
    });

    // add event handlers
    // TODO
})(jQuery);