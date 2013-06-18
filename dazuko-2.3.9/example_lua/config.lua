-- ----- config.lua ---------------------------------------------
-- configuration and access handler, used by the example apps

-- this config merely dumps access details

cfg1 = {
	group = 'example:lua',
	mode = 'r',
	mask = dazuko.ON_OPEN + dazuko.ON_CLOSE,
	includes = { os.getenv('PWD') or '/tmp/dazukotest' },
	excludes = { '/proc/', '/dev/' },

	handler = function(acc)
		io.write("\ngot an access:\n")
		table.foreach(acc, print)
		return(0)
	end,
}


-- this config dumps access details and
-- will block access to files with "block" at their pathname's end

function handler2(acc, param)
	local deny

	io.write("\ngot an access:\n")
	table.foreach(acc, print)
	if (string.find(acc['filename'], 'block$')) then
		io.write("will DENY access\n")
		deny = 1
	else
		io.write("will grant access\n")
		deny = 0
	end
	return(deny)
end

cfg2 = {
	group = 'example:lua2',
	mode = 'rw',
	mask = dazuko.ON_OPEN + dazuko.ON_CLOSE,
	includes = { os.getenv('PWD') or '/tmp/dazukotest' },
	excludes = { '/proc/', '/dev/' },

	handler = handler2,
}

-- ----- E O F --------------------------------------------------
