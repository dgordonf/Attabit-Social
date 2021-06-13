SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, u.id, u.username, u.first_name 
FROM posts p 
LEFT JOIN users u ON p.user_id = u.id 
LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
LEFT JOIN
        (
            SELECT  u.username, SUM(p1.value) AS user_score
            FROM    users u
            LEFT JOIN posts p ON p.user_id = u.id
            LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
            GROUP   BY u.username
        ) b ON b.username = u.username
WHERE p.camp_id = 1 
GROUP BY p.post_id;