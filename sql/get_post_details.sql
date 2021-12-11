
SELECT p.post_id, p2.reply_count, pv.down_votes, pv2.up_votes
FROM posts p
LEFT JOIN
	(
		SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
			FROM posts p
			WHERE p.reply_to_id IN ("135", "136", "359", "362", "364", "365")
			GROUP BY p.reply_to_id
	) p2 ON p2.reply_to_id = p.post_id
LEFT JOIN
	(
		SELECT pv.post_id, COUNT(pv.value) AS down_votes
			FROM post_votes pv
			WHERE pv.post_id IN ("135", "136", "359", "362", "364", "365") AND pv.value < 0
			GROUP BY pv.post_id 
	) pv ON pv.post_id = p.post_id
LEFT JOIN
	(
		SELECT pv.post_id, COUNT(pv.value) AS up_votes
			FROM post_votes pv
			WHERE pv.post_id IN (135, 136, 359, 362, 364, 365) AND pv.value > 0
			GROUP BY pv.post_id
	) pv2 ON pv2.post_id = p.post_id	
WHERE p.post_id IN (135, 136, 359, 362, 364, 365) AND p.camp_id = 0;	
	

                                                    
SELECT pv.post_id, pv.user_id, max(pv.added_time) AS last_vote, pv.value
	FROM post_votes pv
	LEFT JOIN 
	(
	SELECT *
	FROM post_votes pv2
	WHERE pv2.post_id IN ("135", "136", "359", "362", "364", "365") AND pv2.value < 0
	) pv2 ON pv.post_id = pv2.post_id AND pv.added_time = pv2.added_time
	WHERE pv.post_id IN ("135", "136", "359", "362", "364", "365") AND pv.value < 0
	GROUP BY pv.post_id AND pv.user_id
                                                    
                                                    