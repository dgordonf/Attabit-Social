SELECT u.id, u.first_name, u.handle, u.profile_photo, u.creation_time
                                                FROM users u
                                                WHERE u.first_name LIKE '%' || 'Dave' || '%' OR u.handle LIKE '%' || 'DAVE' || '%'
                                                ORDER BY u.creation_time ASC