SELECT u.id, u.first_name, u.handle, b.user_score, u.profile_photo, u.creation_time
			FROM users u
			LEFT JOIN
				(
					SELECT u.id, SUM(p1.value) AS user_score
						FROM users u
						LEFT JOIN posts p ON p.user_id = u.id
						LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
						GROUP BY u.id
				) b ON b.id = u.id
			WHERE u.handle LIKE "DAVE" OR u.first_name LIKE "Dave"
			ORDER BY u.creation_time ASC
			LIMIT 50;
		
		
			
SELECT u.id, u.first_name, u.handle, b.user_score, u.profile_photo, u.creation_time
						FROM users u
						LEFT JOIN
							(
								SELECT u.id, SUM(p1.value) AS user_score
									FROM users u
									LEFT JOIN posts p ON p.user_id = u.id
									LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
									GROUP BY u.id
							) b ON b.id = u.id
						WHERE u.id != 8
						ORDER BY b.user_score DESC
						LIMIT 50;			