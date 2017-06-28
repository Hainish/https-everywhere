'use strict'

// Rules are loaded here
let all_rules = null

// how often we should check for new rulesets
const periodicity = 10

// jwk key loaded from keys.js
const imported_keys = {}

async function importKeys() {
  for (const update_channel of update_channels) {
    imported_keys[update_channel.name] = await window.crypto.subtle.importKey(
      "jwk",
      update_channel.jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"},
      },
      false,
      ["verify"]
    );
  }
}

// Waits ms milliseconds.
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))

// Get an object stored in localstorage
const getStoredLocalObject = object_key => new Promise(resolve => 
  chrome.storage.local.get(object_key, root => resolve(root[object_key]))
);

// Set an object stored in localstorage
const setStoredLocalObject = (object_key, object_value) => new Promise(resolve => {
  const object = {}
  object[object_key] = object_value
  chrome.storage.local.set(object, resolve)
});

// Determine the time until we should check for new rulesets
async function timeToNextCheck() {
  const last_checked = await getStoredLocalObject('last-checked')
  if(last_checked === undefined) {
    return 0
  } else {
    const current_timestamp = Date.now() / 1e3
    const secs_since_last_checked = current_timestamp - last_checked
    return Math.max(0, periodicity - secs_since_last_checked)
  }
}

// Check for new rulesets. If found, return the timestamp. If not, return false
async function checkForNewRulesets(update_channel) {

  const rulesets_timestamp = await (await fetch(update_channel.update_path_prefix + "/rulesets-timestamp")).json()

  if((await getStoredLocalObject('rulesets-timestamp: ' + update_channel.name) || 0) < rulesets_timestamp){
    return rulesets_timestamp
  } else {
    return false
  }
}

// Download and return new rulesets
async function getNewRulesets(rulesets_timestamp, update_channel) {

  setStoredLocalObject('rulesets-timestamp: ' + update_channel.name, rulesets_timestamp)

  const signature = await (await fetch(update_channel.update_path_prefix + "/default.rulesets")).arrayBuffer()
  const rulesets = await (await fetch(update_channel.update_path_prefix + "/rulesets-signature.sha256")).arrayBuffer()

  return {
    'signature': signature,
    'rulesets': rulesets
  }
}

// Returns a promise which verifies that the rulesets have a valid EFF
// signature, and if so, stores them and returns true.
// Otherwise, it throws an exception.

async function verifyAndStoreNewRulesets(new_rulesets, update_channel){
  const key = await imported_keys[update_channel.name]

  const isValid = await window.crypto.subtle.verify({ name:'RSASSA-PKCS1-v1_5' }, publicKey, new_rulesets.signature, new_rulesets.rulesets)

  if (!isValid)
  {
    throw new Exception('Downloaded ruleset signature is invalid.')
  }

  console.log('INFO', update_channel.name + ': Downloaded ruleset signature checks out. Storing rulesets.')

  const rulesets_string = (new TextDecoder()).decode(new_rulesets.rulesets)
  
  await setStoredLocalObject('rulesets: ' + update_channel.name, rulesets_string)

  return true
}

// Apply the rulesets we have stored.
async function applyStoredRulesets() {
  all_rules = new RuleSets(localStorage)

  for (const update_channel of update_channels) {
      const key = 'rulesets: ' + update_channel.name
      const rulesets = await getStoredLocalObject(key)
      if (rulesets) {
        console.log('INFO', update_channel.name + ': Applying stored rulesets.')

        const rulesets_xml = (new DOMParser()).parseFromString(rulesets, "text/xml")

        all_rules.addFromXml(rulesets_xml, 'xml')
      }
  }

  loadStoredUserRules()
}

// basic workflow for periodic checks
async function performCheck() {
  console.log('INFO', 'Checking for new rulesets.')

  const current_timestamp = Date.now() / 1e3
  await setStoredLocalObject('last-checked', current_timestamp)

  for (const update_channel of update_channels) {
    const new_rulesets_timestamp = await checkForNewRulesets(update_channel)
    if (new_rulesets_timestamp) {
      console.log('INFO', update_channel.name + ': A new ruleset bundle has been released.  Downloading now.')
      const new_rulesets = await getNewRulesets(new_rulesets_timestamp, update_channel)
      await verifyAndStoreNewRulesets(new_rulesets, update_channel)
      await applyStoredRulesets()
    }
  }
};

async function updateLoop() {
  while (true)
  {
    try {
      await performCheck()
    } catch (e) {
      console.log('ERROR', e)
    }

    let time_to_next_check
    try {
      time_to_next_check = await timeToNextCheck()
    } catch (e) {
      console.log('ERROR', e)
      console.log('ERROR', 'timeToNextCheck() failed, waiting ' + periodicity + 'seconds.')

      time_to_next_check = periodicity
    }

    await delay(time_to_next_check * 1e3)
  }
}

async function begin() {
  await importKeys()

  await applyStoredRulesets()

  await updateLoop()
}

begin()
