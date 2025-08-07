import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import type { SignalRepository, WAMessage, WAMessageKey, AddressingMode } from '../Types'
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

/**
 * Extract addressing mode and alternative identities from message stanza
 * Following whatsmeow's approach in message.go:79-92
 */
export const extractAddressingContext = (stanza: BinaryNode, _from: string, _participant?: string) => {
	const addressingMode = (stanza.attrs.addressing_mode as AddressingMode) || 'pn'
	let senderAlt: string | undefined
	let recipientAlt: string | undefined
	
	if (addressingMode === 'lid') {
		// Message is LID-addressed: sender is LID, extract corresponding PN
		senderAlt = stanza.attrs.participant_pn || stanza.attrs.sender_pn
		recipientAlt = stanza.attrs.recipient_pn
	} else {
		// Message is PN-addressed: sender is PN, extract corresponding LID
		senderAlt = stanza.attrs.participant_lid || stanza.attrs.sender_lid
		recipientAlt = stanza.attrs.recipient_lid
	}
	
	return {
		addressingMode,
		senderAlt,
		recipientAlt
	}
}

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
		senderLid: stanza?.attrs?.sender_lid || stanza?.attrs?.peer_recipient_lid,
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
								// Store LID mappings from group messages - add missing device ID to both LID and PN
								if (fullMessage.key.senderLid && author) {
									logger.debug('Storing LID-PN mapping from group message')
									
									// Add device ID to LID: "102765716062358@lid" → "102765716062358:0@lid"
									const lidWithDevice = fullMessage.key.senderLid.includes(':') 
										? fullMessage.key.senderLid 
										: fullMessage.key.senderLid.replace('@lid', ':0@lid')
									
									// Add device ID to PN: "554396160286@s.whatsapp.net" → "554396160286:0@s.whatsapp.net"
									const pnWithDevice = author.includes(':') 
										? author 
										: author.replace('@s.whatsapp.net', ':0@s.whatsapp.net')
									
									logger.debug({ 
										originalSenderLid: fullMessage.key.senderLid,
										lidWithDevice,
										originalAuthor: author,
										pnWithDevice
									}, 'Storing group LID-PN mapping with device IDs for both')
									
									await repository.storeLIDPNMapping(lidWithDevice, pnWithDevice)
								}
								
								msgBuffer = await repository.decryptGroupMessage({
									group: sender,
									authorJid: author,
									msg: content
								})
								break
							case 'pkmsg':
							case 'msg':
								// WHATSMEOW EXACT LOGIC (message.go:284-298) - NO reactive migrations!
								let senderEncryptionJid = sender
								
								// OWN DEVICE OPTIMIZATION: Skip LID logic for our own devices (prevents session corruption)
								const ownPhoneNumber = meId.split('@')[0]?.split(':')[0]
								const targetUser = sender.split('@')[0]?.split(':')[0]
								
								if (ownPhoneNumber && targetUser === ownPhoneNumber) {
									logger.debug({ sender }, '⚡ Own device optimization: Skipping LID logic for own device')
									// Use the provided address directly - don't convert to LID
									senderEncryptionJid = sender
								} else if (sender.includes('@s.whatsapp.net') && !sender.includes('bot')) {
									if (fullMessage.key.senderLid?.includes('@lid')) {
										// SenderAlt (LID) takes priority - whatsmeow line 286-288
										logger.debug({ 
											sender, 
											senderLid: fullMessage.key.senderLid 
										}, 'whatsmeow: Using SenderAlt (LID) for decryption')
										senderEncryptionJid = fullMessage.key.senderLid
										
										// Store mapping - add missing device ID to both LID and PN
										// Add device ID to LID: "102765716062358@lid" → "102765716062358:0@lid"
										const lidWithDevice = fullMessage.key.senderLid.includes(':') 
											? fullMessage.key.senderLid 
											: fullMessage.key.senderLid.replace('@lid', ':0@lid')
										
										// Add device ID to PN: "554396160286@s.whatsapp.net" → "554396160286:0@s.whatsapp.net"
										const pnWithDevice = sender.includes(':') 
											? sender 
											: sender.replace('@s.whatsapp.net', ':0@s.whatsapp.net')
										
										logger.debug({ 
											originalSenderLid: fullMessage.key.senderLid,
											lidWithDevice,
											originalSender: sender,
											pnWithDevice
										}, 'Storing LID-PN mapping with device IDs for both')
										
										await repository.storeLIDPNMapping(lidWithDevice, pnWithDevice)
										
										// WHATSMEOW: Migrate when SenderAlt is present (message.go:288)
										await repository.migrateSession(sender, fullMessage.key.senderLid)
									} else {
										// No SenderAlt, check stored LID mapping - whatsmeow line 289-297  
										const lidMapping = repository.getLIDMappingStore()
										
										// Add device ID to PN for proper lookup during decryption
										const pnForLookup = sender.includes(':') 
											? sender 
											: sender.replace('@s.whatsapp.net', ':0@s.whatsapp.net')
										
										logger.debug({ 
											originalSender: sender,
											pnForLookup 
										}, 'Looking up LID mapping during decryption')
										
										const lidForPN = await lidMapping.getLIDForPN(pnForLookup)
										
										if (lidForPN) {
											logger.debug({ 
												pn: pnForLookup, 
												lid: lidForPN 
											}, 'whatsmeow: Found stored LID mapping for decryption')
											
											// Simple session existence check without actual decryption
											try {
												const lidAddr = repository.jidToSignalProtocolAddress(lidForPN)
												logger.debug({ lidAddr }, '🔍 Checking LID session existence during decryption')
												
												// Use the LID for decryption if mapping exists
												senderEncryptionJid = lidForPN
												fullMessage.key.senderLid = lidForPN
												
												logger.debug({ 
													finalJid: senderEncryptionJid 
												}, '✅ Using LID for decryption based on stored mapping')
											} catch (validationError: any) {
												logger.debug({ 
													lid: lidForPN, 
													fallback: sender, 
													error: validationError?.message 
												}, '⚠️ LID validation failed, using PN for decryption')
											}
										} else {
											logger.debug({ sender: pnForLookup }, 'whatsmeow: No LID mapping found, using PN')
										}
									}
								}
								
								// WHATSMEOW: Single decryption attempt - NO fallbacks or migrations
								logger.debug({ finalSender: senderEncryptionJid }, 'Using resolved sender for decryption')
								
								msgBuffer = await repository.decryptMessage({
									jid: senderEncryptionJid,
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
