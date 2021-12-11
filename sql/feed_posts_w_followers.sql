SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_score, 0 ) as current_user_score, u.first_name, u.handle
				FROM follows f
				LEFT JOIN posts p ON p.user_id = f.following
				LEFT JOIN users u ON p.user_id = u.id 
				LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
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
						SELECT p2.post_id, SUM(p2.value) AS current_user_score
							FROM post_votes p2
							WHERE p2.camp_id = 0 AND p2.user_id = 8
							GROUP BY p2.post_id
						) c on c.post_id = p.post_id     
				WHERE (f.user_id = 8 AND f.follow_value = 1 AND (p.reply_to_id IS NULL)) OR p.user_id = 8 AND p.camp_id = 0 
				GROUP BY p.post_id