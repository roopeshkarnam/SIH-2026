const $ = id => document.getElementById(id)

window.mudra.info().then(info => {
  const choice = document.querySelector(`input[value="${info.mode}"]`) || document.querySelector('input[value="local"]')
  choice.checked = true
  $('address').value = info.address || ''
  if (info.lan.length) $('lan').textContent = info.lan.join(' or ')
})

$('start').addEventListener('click', async () => {
  const mode = document.querySelector('input[name=mode]:checked').value
  $('start').disabled = true
  $('start').textContent = mode === 'join' ? 'Connecting…' : 'Starting the secure service…'
  $('error').textContent = ''
  const result = await window.mudra.start(mode, $('address').value)
  if (!result.ok) {
    $('error').textContent = result.error
    $('start').disabled = false
    $('start').textContent = 'Start'
  }
})
