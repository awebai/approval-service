// All assets and display definitions are local. No external scripts or links.
const status = document.querySelector('#status');
const list = document.querySelector('#requests');
let csrf;
let enrollment;
const locator = decodeURIComponent(location.hash.slice(1));
function bytes(text) {
  const raw = atob(text.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(raw, ch => ch.charCodeAt(0));
}
function encoded(buffer) {
  const input = new Uint8Array(buffer); let raw = '';
  for (let start = 0; start < input.length; start += 4096) raw += String.fromCharCode(...input.subarray(start, start + 4096));
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
async function post(path, value) {
  const response = await fetch(path, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.code ?? 'Request failed');
  return body;
}
function assertion(credential) {
  return {id: encoded(credential.rawId), client_data_json: encoded(credential.response.clientDataJSON), authenticator_data: encoded(credential.response.authenticatorData), signature: encoded(credential.response.signature)};
}
async function get(options) {
  const publicKey = {...options, challenge: bytes(options.challenge)};
  delete publicKey.id; delete publicKey.deadline; delete publicKey.request; delete publicKey.display; delete publicKey.digest;
  if (publicKey.allowCredentials) publicKey.allowCredentials = publicKey.allowCredentials.map(c => ({...c, id: bytes(c.id)}));
  return navigator.credentials.get({publicKey});
}
function show(label, value, parent, technical = true) {
  const title = document.createElement('p'); title.textContent = label; parent.append(title);
  const content = document.createElement('pre'); content.textContent = technical ? JSON.stringify(value, null, 2) : value; parent.append(content);
}
function display(item) {
  const box = document.createElement('article');
  const heading = document.createElement('h2'); heading.textContent = item.display.heading; box.append(heading);
  show('What this approves', item.display.consequence, box, false);
  show('Requester', item.request.requester, box);
  show('Enforcer', item.request.enforcer.audience, box);
  show('Organisation', item.request.organisation, box);
  for (const field of item.display.technical_fields.filter(f => f !== 'organisation')) {
    const value = field.split('.').reduce((v, part) => v?.[part], item.request.act);
    show(field, value, box);
  }
  show('Exact act', item.request.act, box);
  show('Deadline', new Date(item.request.deadline * 1000).toISOString(), box);
  show('Full request commitment', item.digest, box);
  return box;
}
async function refresh() {
  const response = await fetch('/browser/pending', {credentials: 'same-origin'});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.code ?? 'Sign in again');
  list.replaceChildren(); status.textContent = `Signed in as ${body.person}`;
  for (const item of body.requests) {
    const box = display(item);
    for (const [text, act] of [['Approve', 'approve'], ['Deny', 'deny']]) {
      const button = document.createElement('button'); button.textContent = text;
      button.onclick = () => run(async () => {
        const selection = {locator: item.locator, csrf};
        if (act === 'deny') await post('/browser/approval/deny', selection);
        else {
          const options = await post('/browser/approval/options', selection);
          const credential = await get(options);
          await post('/browser/approval/finish', {...selection, id: options.id, assertion: assertion(credential)});
        }
        await refresh();
      });
      box.append(button);
    }
    list.append(box);
  }
}
async function run(action) {
  try { await action(); } catch (error) { status.textContent = error.message; }
}
document.querySelector('#login').onclick = () => run(async () => {
  const options = await post('/browser/login/options', {});
  const credential = await get(options);
  const body = await post('/browser/login/finish', {id: options.id, assertion: assertion(credential), user_handle: encoded(credential.response.userHandle)});
  csrf = body.csrf; await refresh();
});
if (location.pathname === '/enroll' && locator) {
  document.querySelector('#enrollment').hidden = false;
  status.textContent = 'Register a key for the enrollment opened by your issuer.';
}
document.querySelector('#register').onclick = () => run(async () => {
  enrollment = await post('/browser/enrollment/options', {locator});
  const options = enrollment.public_key;
  const credential = await navigator.credentials.create({publicKey: {...options, challenge: bytes(options.challenge), user: {...options.user, id: bytes(options.user.id)}}});
  await post('/browser/enrollment/register', {locator, csrf: enrollment.csrf, registration: {id: encoded(credential.rawId), client_data_json: encoded(credential.response.clientDataJSON), attestation_object: encoded(credential.response.attestationObject)}, client_extension_results: credential.getClientExtensionResults()});
  status.textContent = 'Key registered. Register a second key if available, then ask your issuer to prepare enrollment confirmation.';
});
document.querySelector('#confirm').onclick = () => run(async () => {
  enrollment = await post('/browser/enrollment/options', {locator});
  const options = await post('/browser/enrollment/confirmation/options', {locator, csrf: enrollment.csrf});
  list.replaceChildren(display({request: options.request, digest: options.digest, display: options.display}));
  const button = document.createElement('button'); button.textContent = 'Confirm with your key';
  button.onclick = () => run(async () => {
    const credential = await get(options);
    await post('/browser/enrollment/confirmation/finish', {locator, csrf: enrollment.csrf, id: options.id, assertion: assertion(credential)});
    status.textContent = 'Enrollment confirmed. Your issuer must commit your identity and activate the enrollment before sign-in.';
    list.replaceChildren();
  });
  list.append(button);
});
