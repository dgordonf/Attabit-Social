SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, u.first_name, u.handle, u.profile_photo, p.creation_time, p.post_text, p.media_id, b.user_score, COALESCE(c.current_user_score, 0 ) as current_user_score, p2.reply_count, pv.down_votes, pv2.up_votes
                                                    FROM posts p
				                                    LEFT JOIN users u ON p.user_id = u.id 
                                                    LEFT JOIN
														(
															SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
																FROM posts p
																WHERE p.reply_to_id = 389
																GROUP BY p.reply_to_id
														) p2 ON p2.reply_to_id = p.post_id
													LEFT JOIN
														(
															SELECT pv.post_id, COUNT(pv.value) AS down_votes
																FROM post_votes pv
																WHERE pv.post_id = 389 AND pv.value < 0
																GROUP BY pv.post_id
														) pv ON pv.post_id = p.post_id
													LEFT JOIN
														(
															SELECT pv.post_id, COUNT(pv.value) AS up_votes
																FROM post_votes pv
																WHERE pv.post_id = 389 AND pv.value > 0
																GROUP BY pv.post_id
														) pv2 ON pv2.post_id = p.post_id
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
																WHERE p2.user_id = 8
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id 
                                                    WHERE p.post_id = 389 AND p.is_deleted = 0;      
                                

