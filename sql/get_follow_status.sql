SELECT u.handle, COALESCE(f.follow_value, 0 ) as follow_status
	FROM users u
	LEFT JOIN follows f ON f.following = u.id
	WHERE f.user_id = 8 AND u.handle = 'dave' AND f.last_update_time IS NULL