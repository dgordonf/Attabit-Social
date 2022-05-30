SELECT p.post_id, p.user_id, u.first_name, u.handle, u.profile_photo, p.reply_to_id, p.creation_time, pv.post_score, p.post_text, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, 
	FROM posts p
	LEFT JOIN users u ON u.id = p.user_id 
	LEFT JOIN 
		(
			SELECT f.following, f.follow_value
				FROM follows f
				WHERE f.user_id = 8 AND f.follow_value = 1
		) f ON f.following = p.user_id 
	LEFT JOIN
		(
			SELECT pv.post_id, SUM(pv.value) AS post_score
				FROM post_votes pv
				GROUP BY pv.post_id
		) pv ON post_id = pv.post_id
	LEFT JOIN
			(
				SELECT u.id, SUM(p1.value) AS user_score
					FROM users u
					LEFT JOIN posts p ON p.user_id = u.id
					LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
					GROUP BY u.id
			) b ON b.id = u.id
	LEFT JOIN
			(
			SELECT p2.post_id, SUM(p2.value) AS current_user_vote
				FROM post_votes p2
				WHERE p2.user_id = 8
				GROUP BY p2.post_id
			) c on c.post_id = p.post_id 
	WHERE ((f.follow_value = 1 AND f.user_id = 8) OR p.user_id = 8) AND p.reply_to_id IS NULL AND p.is_deleted = 0;
	