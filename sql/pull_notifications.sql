SELECT n.notification_id, n.creation_time, u.profile_photo, u.handle, n.event_type_id, n.reference_post_id, n.seen
FROM notifications n
LEFT JOIN users u ON u.id = n.triggered_by_user_id
ORDER BY n.creation_time DESC
LIMIT 25