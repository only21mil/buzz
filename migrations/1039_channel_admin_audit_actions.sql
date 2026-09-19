-- Community-authorized channel commands share the moderation audit trail.
ALTER TABLE moderation_actions DROP CONSTRAINT moderation_actions_action_check;
ALTER TABLE moderation_actions ADD CONSTRAINT moderation_actions_action_check CHECK (action IN (
    'delete_message', 'kick', 'ban', 'unban', 'timeout', 'untimeout',
    'dismiss_report', 'escalate', 'resolve:delete', 'resolve:kick',
    'resolve:ban', 'resolve:timeout', 'add_member', 'edit_metadata', 'delete_channel'
));
