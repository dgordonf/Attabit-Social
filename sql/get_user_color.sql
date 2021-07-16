SELECT * FROM camp_directory cd 
LEFT JOIN
	(	SELECT  u.id, u.username, SUM(p1.value) AS user_score
		FROM    users u
		LEFT JOIN posts p ON p.user_id = u.id
		LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
		GROUP   BY u.username
	) b ON b.id = cd.user_id
WHERE cd.camp_id = 1 AND cd.user_id = 8;


INSERT INTO camp_directory (camp_id, user_id) VALUES (%s, %s);", (1, user_id))