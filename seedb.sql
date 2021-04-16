SELECT * FROM search_index WHERE article_id = 'R_dc2ae0036b665a4277b784de5f6f19aa';

DELETE FROM sentences WHERE article_id = 'R_dc2ae0036b665a4277b784de5f6f19aa';
DELETE FROM search_index WHERE article_id = 'R_dc2ae0036b665a4277b784de5f6f19aa';

SELECT * FROM sentences WHERE article_id = 'R_dc2ae0036b665a4277b784de5f6f19aa';

DELETE FROM sentences WHERE author_id < 1;
DELETE FROM search_index WHERE author_id < 1;