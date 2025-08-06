import type { AddressingMode } from '../Types/Message'
import type { SignalKeyStoreWithTransaction } from '../Types/Auth'

export interface ConversationContext {
	preferredAddressingMode?: AddressingMode
	lastSeenAddressingMode?: AddressingMode
	lastMessageTimestamp?: number
}

/**
 * Manages conversation context including preferred addressing modes
 * Following whatsmeow's approach of using message context for addressing decisions
 */
export class ConversationContextManager {
	constructor(private keys: SignalKeyStoreWithTransaction) {}

	/**
	 * Get conversation context for a JID
	 */
	async getContext(jid: string): Promise<ConversationContext | null> {
		try {
			const normalizedJid = this.normalizeJid(jid)
			const result = await this.keys.get('conversation-context', [normalizedJid])
			return (result[normalizedJid] as ConversationContext) || null
		} catch (error) {
			console.warn(`Failed to get conversation context for ${jid}:`, error)
			return null
		}
	}

	/**
	 * Update conversation context from incoming message
	 * This is called when receiving messages to track addressing mode
	 */
	async updateFromIncomingMessage(
		jid: string, 
		addressingMode: AddressingMode,
		timestamp: number
	): Promise<void> {
		try {
			const normalizedJid = this.normalizeJid(jid)
			const existing = await this.getContext(jid) || {}
			
			const updated: ConversationContext = {
				...existing,
				lastSeenAddressingMode: addressingMode,
				preferredAddressingMode: addressingMode, // Use the mode the contact is using
				lastMessageTimestamp: timestamp
			}

			await this.keys.set({
				'conversation-context': {
					[normalizedJid]: updated
				}
			})

			console.log(`📝 Updated conversation context for ${jid}: ${addressingMode}`)
		} catch (error) {
			console.warn(`Failed to update conversation context for ${jid}:`, error)
		}
	}

	/**
	 * Get preferred addressing mode for a contact
	 * Returns null if no context exists (fallback to session-based logic)
	 */
	async getPreferredAddressingMode(jid: string): Promise<AddressingMode | null> {
		const context = await this.getContext(jid)
		return context?.preferredAddressingMode || null
	}

	/**
	 * Clear context for a JID (useful for testing or reset scenarios)
	 */
	async clearContext(jid: string): Promise<void> {
		try {
			const normalizedJid = this.normalizeJid(jid)
			await this.keys.set({
				'conversation-context': {
					[normalizedJid]: null
				}
			})
		} catch (error) {
			console.warn(`Failed to clear conversation context for ${jid}:`, error)
		}
	}

	/**
	 * Normalize JID by removing device suffix for context storage
	 * Context is per-user, not per-device
	 */
	private normalizeJid(jid: string): string {
		// Remove device suffix (e.g., ":1.0") for context storage
		return jid.split(':')[0] || jid
	}
}