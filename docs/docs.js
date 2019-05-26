const utils = rabbit.utils,
cl = console.log,
ce = console.error;

function isEmpty(i){
  let item = $('#'+ i).val();
  if(item === ''){
    return true;
  }
  return false
}

function completetest(){
  let txt = $('#text').val(),
  key = $('#key').val(),
  dgs = $('#digest').val(),
  pkey, status;

  $('#pkey').val(utils.randomBytes(32));
  pkey = $('#pkey').val();

  if(isEmpty('text')){
    $('#status').val('plaintext cannot be empty');
    return;
  }
  if(isEmpty('key')){
    $('#status').val('key cannot be empty');
    return;
  }

  // encrypt/decrypt with poly1305 ~ callback
  rabbit.encPoly(txt, key, pkey, dgs, function(err, res){
    if(err){return ce(err)};
    let verify = rabbit.poly1305.signSync(res.ctext, res.ctext.length, pkey, dgs);
    rabbit.decPoly(res.ctext, key, res.sig, verify, dgs, function(err, plain){
      if(err){
        $('#status').val('error')
        ce(err)
        return;
      };
      cl(plain)
      $('#psig').val(res.sig)
      $('#ciphertext').val(res.ctext)
      $('#res').text(JSON.stringify(res,0,2))
      $('#status').val('success')

    });

  });

}

let sigres = {
  pkey: 'poly1305 key',
  psig: 'poly1305 signature'
}

$('body').append('<div class="container-fluid"><h1 class="text-center mt-4 mb-4">rabbit-cipher</h1><div class="row main"></div></div>')

$('.main').append('<div class="col-sm-6"><label>Digest</label><select class="form-control" id="digest"></select></div><div class="col-sm-6"><label>status</label><input class="form-control" id="status"></div>')

$.each(['hex', 'base64', 'bytes', 'binary', 'uint8'], function(e,i){
  $('#digest').append('<option value="'+ i +'">'+ i +'</option>')
})

$.each(['text', 'key', 'ciphertext'], function(e,i){
  $('.main').append('<div class="col-sm-4 mt-4"><label>'+ i +'</label><textarea class="form-control" id="'+ i +'" rows="6"></textarea></div>')
})

$.each(sigres, function(e,i){
  $('.main').append('<div class="col-sm-6 mt-4"><label>'+ i +'</label><input class="form-control" id="'+ e +'"></div>')
})

$('.main').append('<div class="col-sm-12 mt-4"><label>result</label><pre><code id="res"></code></pre></div>')

$.each(['text', 'key'], function(e,i){
  $('#' + i).on('keyup', function(event) {
    completetest()
  });
})
