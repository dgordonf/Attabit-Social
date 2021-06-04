SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.creation_time, p.post_text, p.opacity, u.id, u.username, u.first_name FROM posts p 
LEFT JOIN users u ON u.id  = p.user_id
WHERE p.camp_id = '1'; 

SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.creation_time, p.post_text, SUM(pv.value) AS opacity, u.id, u.username, u.first_name FROM posts p 
LEFT JOIN users u ON p.user_id = u.id 
LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id
WHERE p.camp_id = '1'
GROUP BY p.post_id;

