/**
 * The add-on's memory of who normally writes to this user. It is stored in the user's own private
 * add-on storage (no database, no extra permission) and holds only short hashes, never addresses
 * or names. The backend receives facts about the current sender, not the memory itself.
 */
const SENDERS_KEY = 'knownSenders';
const NAMES_KEY = 'knownNames';
const LIST_SEPARATOR = ',';
const PAIR_SEPARATOR = ':';
const HASH_CHARS = 12;
// Apps Script keeps at most 9 KB per stored value: ~13 characters per sender, ~26 per name+domain pair.
const MAX_KNOWN_SENDERS = 600;
const MAX_KNOWN_NAMES = 300;
// "Name <address@domain>", or a bare address.
const SENDER_WITH_NAME = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/;

/** @return {{known_sender_count: number, address_seen_before: boolean, name_seen_with_other_domain: boolean}|null} */
function readSenderHistory(message) {
  try {
    const sender = identifySender(message);
    if (!sender) {
      return null;
    }
    const senders = readList(SENDERS_KEY);
    const names = readList(NAMES_KEY);
    return {
      known_sender_count: senders.length,
      address_seen_before: senders.includes(sender.addressHash),
      name_seen_with_other_domain: wasSeenFromAnotherDomain(sender, names),
    };
  } catch (error) {
    // The memory is a bonus signal: if it fails, the analysis still runs without it.
    console.error('Reading sender history failed: ' + error.message);
    return null;
  }
}

/** Remembers a sender. Called only for emails judged safe, so an attacker can't get a bad sender remembered. */
function rememberSender(message) {
  try {
    const sender = identifySender(message);
    if (!sender) {
      return;
    }
    addToList(SENDERS_KEY, sender.addressHash, MAX_KNOWN_SENDERS);
    if (sender.nameHash) {
      addToList(NAMES_KEY, sender.nameHash + PAIR_SEPARATOR + sender.domainHash, MAX_KNOWN_NAMES);
    }
  } catch (error) {
    console.error('Remembering sender failed: ' + error.message);
  }
}

function identifySender(message) {
  const from = message.getFrom();
  const match = from.match(SENDER_WITH_NAME);
  const address = (match ? match[2] : from).trim().toLowerCase();
  const name = match ? match[1].trim().toLowerCase() : '';
  const atIndex = address.lastIndexOf('@');
  if (atIndex < 1) {
    return null;
  }
  return {
    addressHash: shortHash(address),
    domainHash: shortHash(address.slice(atIndex + 1)),
    // A display name that is just an address says nothing about who the sender is.
    nameHash: name && !name.includes('@') ? shortHash(name) : '',
  };
}

function wasSeenFromAnotherDomain(sender, names) {
  if (!sender.nameHash) {
    return false;
  }
  const sameName = names.filter((pair) => pair.startsWith(sender.nameHash + PAIR_SEPARATOR));
  const thisPair = sender.nameHash + PAIR_SEPARATOR + sender.domainHash;
  return sameName.length > 0 && !sameName.includes(thisPair);
}

function shortHash(text) {
  return sha256Hex(Utilities.newBlob(text).getBytes()).slice(0, HASH_CHARS);
}

function readList(key) {
  const stored = PropertiesService.getUserProperties().getProperty(key);
  return stored ? stored.split(LIST_SEPARATOR) : [];
}

function addToList(key, entry, maxEntries) {
  const entries = readList(key);
  if (entries.includes(entry)) {
    return;
  }
  entries.push(entry);
  // When full, the oldest entries are forgotten first.
  const kept = entries.slice(-maxEntries);
  PropertiesService.getUserProperties().setProperty(key, kept.join(LIST_SEPARATOR));
}
