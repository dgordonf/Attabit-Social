SELECT a.added_time as date, count(distinct a.user_id) as count
FROM (

SELECT pv.added_time, pv.user_id 
FROM post_votes pv

UNION

SELECT p.creation_time, p.user_id
FROM posts p

) a
WHERE (a.added_time >= str_to_date(concat(year(now(6)), '-', ((quarter(now(6)) * 3) - 2), '-01'), '%Y-%m-%d')
   AND a.added_time < str_to_date(concat(year(date_add(now(6), INTERVAL 1 quarter)), '-', ((quarter(date_add(now(6), INTERVAL 1 quarter)) * 3) - 2), '-01'), '%Y-%m-%d'))
GROUP BY date(a.added_time)
ORDER BY date(a.added_time) ASC