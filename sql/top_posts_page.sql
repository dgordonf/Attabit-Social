SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                                    FROM posts p
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
                                                    		SELECT p2.post_id, SUM(p2.value) AS current_user_vote
																FROM post_votes p2
																WHERE p2.camp_id = 0 AND p2.user_id = 8
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id 
                                                    WHERE (p.reply_to_id IS NULL) AND p.is_deleted = 0 
                                                    AND p.creation_time >= '2022-01-01T05:00:00.000'  
      												AND p.creation_time <= '2022-01-02T05:00:00.000'
                                                    GROUP BY p.post_id
                                                    ORDER BY post_score DESC
                                                    LIMIT 100;       
                                                    
                                                    
           
                                                    
                                                    