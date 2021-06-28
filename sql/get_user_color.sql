SELECT * FROM camp_directory cd 
LEFT JOIN
	(	SELECT  u.username, SUM(p1.value) AS user_score
		FROM    users u
		LEFT JOIN posts p ON p.user_id = u.id
		LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
		GROUP   BY u.username
	) b ON b.username = u.username
WHERE cd.camp_id = 1 AND cd.user_id = 8;