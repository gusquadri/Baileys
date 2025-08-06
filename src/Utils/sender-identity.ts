import { jidDecode } from '../WABinary'
import type { AuthenticationCreds } from '../Types'

/**
 * WhatsApp-style sender identity determination based on recipient JID
 * Based on whatsmeow's sendDM logic
 * 
 * This function determines which sender identity (PN or LID) should be used
 * when sending messages to a specific recipient JID.
 */
export function getSenderIdentity(recipientJid: string, creds: AuthenticationCreds): string {
	const defaultSender = creds.me?.id     // Default: use PN
	const lidSender = creds.me?.lid        // Alternative: use LID
	
	const decoded = jidDecode(recipientJid)
	if (!decoded) {
		// Fallback to default sender if JID is invalid
		return defaultSender || lidSender || ''
	}
	
	const { server } = decoded
	
	// WhatsApp's logic: Use LID for hidden user server (@lid)
	if (server === 'lid') {
		return lidSender || defaultSender || ''
	}
	
	// Default: use phone number for regular contacts (@s.whatsapp.net)
	return defaultSender || ''
}

/**
 * Determine if recipient should receive messages via LID addressing
 * Based on whatsmeow's logic for addressing mode determination
 */
export function shouldUseLIDAddressing(recipientJid: string): boolean {
	const decoded = jidDecode(recipientJid)
	if (!decoded) return false
	
	const { server } = decoded
	return server === 'lid'
}

/**
 * Get the appropriate sender JID for a message based on recipient
 * This ensures consistent sender identity to prevent chat separation
 */
export function getMessageSenderJid(recipientJid: string, creds: AuthenticationCreds): string {
	return getSenderIdentity(recipientJid, creds)
}