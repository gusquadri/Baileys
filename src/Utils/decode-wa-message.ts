import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import type { SignalRepository, WAMessage, WAMessageKey } from '../Types'
import {
	areJidsSameUser,
	type BinaryNode,
	isJidBroadcast,
	isJidGroup,
	isJidMetaIa,
	isJidNewsletter,
	isJidStatusBroadcast,
	isJidUser,
	isLidUser
} from '../WABinary'
import { unpadRandomMax16 } from './generics'
import type { ILogger } from './logger'

export const NO_MESSAGE_FOUND_ERROR_TEXT = 'Message absent from node'
export const MISSING_KEYS_ERROR_TEXT = 'Key used already or never filled'

export const NACK_REASONS = {
	ParsingError: 487,
	UnrecognizedStanza: 488,
	UnrecognizedStanzaClass: 489,
	UnrecognizedStanzaType: 490,
	InvalidProtobuf: 491,
	InvalidHostedCompanionStanza: 493,
	MissingMessageSecret: 495,
	SignalErrorOldCounter: 496,
	MessageDeletedOnPeer: 499,
	UnhandledError: 500,
	UnsupportedAdminRevoke: 550,
	UnsupportedLIDGroup: 551,
	DBOperationFailed: 552
}

type MessageType =
	| 'chat'
	| 'peer_broadcast'
	| 'other_broadcast'
	| 'group'
	| 'direct_peer_status'
	| 'other_status'
	| 'newsletter'

/**
 * Decode the received node as a message.
 * @note this will only parse the message, not decrypt it
 */
export function decodeMessageNode(stanza: BinaryNode, meId: string, meLid: string) {
	let msgType: MessageType
	let chatId: string
	let author: string

	const msgId = stanza.attrs.id
	const from = stanza.attrs.from
	const participant: string | undefined = stanza.attrs.participant
	const recipient: string | undefined = stanza.attrs.recipient

	const isMe = (jid: string) => areJidsSameUser(jid, meId)
	const isMeLid = (jid: string) => areJidsSameUser(jid, meLid)

	if (isJidUser(from) || isLidUser(from)) {
		if (recipient && !isJidMetaIa(recipient)) {
			if (!isMe(from!) && !isMeLid(from!)) {
				throw new Boom('receipient present, but msg not from me', { data: stanza })
			}

			chatId = recipient
		} else {
			chatId = from!
		}

		msgType = 'chat'
		author = from!
	} else if (isJidGroup(from)) {
		if (!participant) {
			throw new Boom('No participant in group message')
		}

		msgType = 'group'
		author = participant
		chatId = from!
	} else if (isJidBroadcast(from)) {
		if (!participant) {
			throw new Boom('No participant in group message')
		}

		const isParticipantMe = isMe(participant)
		if (isJidStatusBroadcast(from!)) {
			msgType = isParticipantMe ? 'direct_peer_status' : 'other_status'
		} else {
			msgType = isParticipantMe ? 'peer_broadcast' : 'other_broadcast'
		}

		chatId = from!
		author = participant
	} else if (isJidNewsletter(from)) {
		msgType = 'newsletter'
		chatId = from!
		author = from!
	} else {
		throw new Boom('Unknown message type', { data: stanza })
	}

	const fromMe = (isLidUser(from) ? isMeLid : isMe)((stanza.attrs.participant || stanza.attrs.from)!)
	const pushname = stanza?.attrs?.notify

	const key: WAMessageKey = {
		remoteJid: chatId,
		fromMe,
		id: msgId,
		senderLid: stanza?.attrs?.sender_lid,
		senderPn: stanza?.attrs?.sender_pn  || stanza?.attrs?.peer_recipient_pn,
		participant,
		participantPn: stanza?.attrs?.participant_pn,
		participantLid: stanza?.attrs?.participant_lid,
		...(msgType === 'newsletter' && stanza.attrs.server_id ? { server_id: stanza.attrs.server_id } : {})
	}

	const fullMessage: WAMessage = {
		key,
		messageTimestamp: +stanza.attrs.t!,
		pushName: pushname,
		broadcast: isJidBroadcast(from)
	}

	if (key.fromMe) {
		fullMessage.status = proto.WebMessageInfo.Status.SERVER_ACK
	}

	return {
		fullMessage,
		author,
		sender: msgType === 'chat' ? author : chatId
	}
}

export const decryptMessageNode = (
	stanza: BinaryNode,
	meId: string,
	meLid: string,
	repository: SignalRepository,
	logger: ILogger
) => {
	const { fullMessage, author, sender } = decodeMessageNode(stanza, meId, meLid)
	return {
		fullMessage,
		category: stanza.attrs.category,
		author,
		async decrypt() {
			let decryptables = 0
			if (Array.isArray(stanza.content)) {
				for (const { tag, attrs, content } of stanza.content) {
					if (tag === 'verified_name' && content instanceof Uint8Array) {
						const cert = proto.VerifiedNameCertificate.decode(content)
						const details = proto.VerifiedNameCertificate.Details.decode(cert.details!)
						fullMessage.verifiedBizName = details.verifiedName
					}

					if (tag === 'unavailable' && attrs.type === 'view_once') {
						fullMessage.key.isViewOnce = true
					}

					if (tag !== 'enc' && tag !== 'plaintext') {
						continue
					}

					if (!(content instanceof Uint8Array)) {
						continue
					}

					decryptables += 1

					let msgBuffer: Uint8Array

					try {
						const e2eType = tag === 'plaintext' ? 'plaintext' : attrs.type
						switch (e2eType) {
							case 'skmsg':
								console.log(`🔍 Group message decryption - checking for LID-PN mapping:`)
								console.log(`  senderLid: ${fullMessage.key.senderLid || 'NOT PRESENT'}`)
								console.log(`  participant: ${fullMessage.key.participant || 'NOT PRESENT'}`)
								console.log(`  sender: ${sender}`)
								console.log(`  author: ${author}`)
								
								// Store LID-PN mapping for group messages too
								if (fullMessage.key.senderLid && author) {
									console.log(`📝 Storing LID-PN mapping from group message`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, author)
								} else if (fullMessage.key.senderLid && fullMessage.key.participant) {
									console.log(`📝 Storing LID-PN mapping from group message (participant)`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, fullMessage.key.participant)
								} else {
									console.log(`⚠️ Group message - not storing mapping (missing data)`)
								}
								
								msgBuffer = await repository.decryptGroupMessage({
									group: sender,
									authorJid: author,
									msg: content
								})
								break
							case 'pkmsg':
							case 'msg':
								// ALWAYS USE SENDER ADDRESS: This is the exact address used for encryption
								// No fallback to author - sender is the actual encryption address
								const user = sender
								console.log(`📱 Using sender address for decryption: ${user}`)
								
								// Store LID-PN mapping if we have both identities (for future reference)
								if (fullMessage.key.senderLid && sender !== fullMessage.key.senderLid) {
									console.log(`📝 Storing LID-PN mapping: ${fullMessage.key.senderLid} ↔ ${sender}`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, sender)
								}
								
								// Store LID-PN mapping if we discover both identities
								console.log(`🔍 Individual message decryption - checking for LID-PN mapping:`)
								console.log(`  senderLid: ${fullMessage.key.senderLid || 'NOT PRESENT'}`)
								console.log(`  participant: ${fullMessage.key.participant || 'NOT PRESENT'}`)
								console.log(`  sender: ${sender}`)
								console.log(`  author: ${author}`)
								
								// Try multiple combinations to find LID-PN pairs
								if (fullMessage.key.senderLid && fullMessage.key.participant) {
									console.log(`📝 Storing LID-PN mapping from individual message (participant)`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, fullMessage.key.participant)
								} else if (fullMessage.key.senderLid && author) {
									console.log(`📝 Storing LID-PN mapping from individual message (author)`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, author)
								} else if (fullMessage.key.senderLid && sender) {
									console.log(`📝 Storing LID-PN mapping from individual message (sender)`)
									await repository.storeLIDPNMapping(fullMessage.key.senderLid, sender)
								} else {
									console.log(`⚠️ Individual message - not storing mapping (missing data)`)
									console.log(`  Available: senderLid=${!!fullMessage.key.senderLid}, participant=${!!fullMessage.key.participant}, author=${!!author}, sender=${!!sender}`)
								}
								
								msgBuffer = await repository.decryptMessage({
									jid: user,
									type: e2eType,
									ciphertext: content
								})
								break
							case 'plaintext':
								msgBuffer = content
								break
							default:
								throw new Error(`Unknown e2e type: ${e2eType}`)
						}

						let msg: proto.IMessage = proto.Message.decode(
							e2eType !== 'plaintext' ? unpadRandomMax16(msgBuffer) : msgBuffer
						)
						msg = msg.deviceSentMessage?.message || msg
						if (msg.senderKeyDistributionMessage) {
							//eslint-disable-next-line max-depth
							try {
								await repository.processSenderKeyDistributionMessage({
									authorJid: author,
									item: msg.senderKeyDistributionMessage
								})
							} catch (err) {
								logger.error({ key: fullMessage.key, err }, 'failed to decrypt message')
							}
						}

						if (fullMessage.message) {
							Object.assign(fullMessage.message, msg)
						} else {
							fullMessage.message = msg
						}
					} catch (err: any) {
						logger.error({ key: fullMessage.key, err }, 'failed to decrypt message')
						fullMessage.messageStubType = proto.WebMessageInfo.StubType.CIPHERTEXT
						fullMessage.messageStubParameters = [err.message]
					}
				}
			}

			// if nothing was found to decrypt
			if (!decryptables) {
				fullMessage.messageStubType = proto.WebMessageInfo.StubType.CIPHERTEXT
				fullMessage.messageStubParameters = [NO_MESSAGE_FOUND_ERROR_TEXT]
			}
		}
	}
}
