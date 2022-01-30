SELECT u.id, u.first_name, u.handle, COALESCE(b.user_score, 0) as user_score, u.profile_photo, u.creation_time, COALESCE(f.follow_value, 0) as follow_value
			FROM users u
			LEFT JOIN
				(
					SELECT u.id, SUM(p1.value) AS user_score
						FROM users u
						LEFT JOIN posts p ON p.user_id = u.id
						LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
						GROUP BY u.id
				) b ON b.id = u.id
			LEFT JOIN (
					SELECT f.following, f.follow_value
					FROM follows f
					WHERE f.user_id = 8 AND f.last_update_time IS NULL
					) f ON f.following = u.id
			WHERE u.handle LIKE "DAVE" OR u.first_name LIKE "Dave"
			ORDER BY u.creation_time ASC
			LIMIT 50;
		
		
			
SELECT u.id, u.first_name, u.handle, COALESCE(b.user_score, 0) as user_score, u.profile_photo, u.creation_time, COALESCE(f.follow_value, 0) as follow_value
						FROM users u
						LEFT JOIN
							(
								SELECT u.id, SUM(p1.value) AS user_score
									FROM users u
									LEFT JOIN posts p ON p.user_id = u.id
									LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
									GROUP BY u.id
							) b ON b.id = u.id
						LEFT JOIN (
							SELECT f.following, f.follow_value
							FROM follows f
							WHERE f.user_id = 8 AND f.last_update_time IS NULL
							) f ON f.following = u.id
						ORDER BY b.user_score DESC
						LIMIT 100;			