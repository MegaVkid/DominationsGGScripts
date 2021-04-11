local info = gg.getTargetInfo()

--hi
gg.alert("By map220v")
gg.setVisible(true)

local memFrom, memTo, lib, num, lim, results, src, ok = 0, -1, nil, 0, 32, {}, nil, false
function name(n)
	if lib ~= n then
		lib = n
		print("\nPatch library "..lib..":\n")
		local ranges = gg.getRangesList(lib)
		if #ranges == 0 then
			print("Error: "..lib.." are not found!")
			os.exit()
		else
			memFrom = ranges[1].start
			memTo = ranges[#ranges]["end"]
		end
	end
end
function hex2tbl(hex)
	local ret = {}
	hex:gsub("%S%S", function (ch)
		ret[#ret + 1] = ch
		return ""
	end)
	return ret
end
function original(orig)
	local tbl = hex2tbl(orig)
	gg.clearResults()
	local len = #tbl
	if len == 0 then return end
	local used = len
	if len > lim then used = lim end
	local s = ''
	for i = 1, used do
		if i ~= 1 then s = s..";" end
		local v = tbl[i]
		if v == "??" or v == "**" then v = "0~~0" end		
		s = s..v.."h"
	end
	s = s.."::"..used
	gg.searchNumber(s, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, memFrom, memTo)
	
	if len > used then
		for i = used + 1, len do
			local v = tbl[i]
			if v == "??" or v == "**" then
				v = 256
			else
				v = ("0x"..v) + 0
				if v > 127 then v = v - 256 end
			end
			tbl[i] = v
		end
	end
	
	local found = gg.getResultCount();
	
	results = {}
	local count = 0
	
	local checked = 0
	while true do
		if checked >= found then
			break
		end
		local all = gg.getResults(100000)
		local total = #all
		local start = checked
		if checked + used > total then
			break
		end
		
		while start < total do		
			local good = true
			local offset = all[1 + start].address - 1
			if used < len then			
				local get = {}
				for i = lim + 1, len do
					get[i - lim] = {address = offset + i, flags = gg.TYPE_BYTE, value = 0}
				end
				get = gg.getValues(get)
				
				for i = lim + 1, len do
					local ch = tbl[i]
					if ch ~= 256 and get[i - lim].value ~= ch then
						good = false
						break
					end
				end
			end
			if good then
				count = count + 1
				results[count] = offset
				checked = checked + used
			else
				local del = {}
				for i = 1, used do
					del[i] = all[i + start]
				end
				gg.removeResults(del)
			end
			start = start + used
		end
	end
	gg.clearResults()
end
function replaced(repl)
	num = num + 1
	local msg = "\nPattern N"..num..":"
	if #results == 0 then
		print(msg.." Not found.")
		return
	end
	print(msg)
	local tbl = hex2tbl(repl)
	
	if src ~= nil then
		local source = hex2tbl(src)
		for i, v in ipairs(tbl) do
			if v ~= "??" and v ~= "**" and v == source[i] then tbl[i] = "**" end
		end
		src = nil
	end
	
	local cnt = #tbl
	local set = {}
	local s = 0
	for _, addr in ipairs(results) do
		print("\tOffset: "..string.format("%x", addr + 1).."\n")		
		for i, v in ipairs(tbl) do
			if v ~= "??" and v ~= "**" then
				s = s + 1
				set[s] = {
					["address"] = addr + i, 
					["value"] = v.."h",
					["flags"] = gg.TYPE_BYTE,
				}
			end
		end		
	end
	if s ~= 0 then gg.setValues(set) end
	ok = true
end
gg.setRanges(gg.REGION_CODE_APP)

name("libil2cpp.so")
--Сам хак!
original("F0 4F 2D E9 1C B0 8D E2 04 D0 4D E2 04 8B 2D ED 08 D0 4D E2 00 A0 A0 E1")--0x11D5F60 (int)ConvertResourcesToGems
replaced("00 00 A0 E3 1E FF 2F E1 04 D0 4D E2 04 8B 2D ED 08 D0 4D E2 00 A0 A0 E1")--return 0
original("F0 4F 2D E9 1C B0 8D E2 04 D0 4D E2 06 8B 2D ED 02 40 A0 E1 F8 25 9F E5")--0x11D56B8 (int)ConvertTimeToGems
replaced("00 00 A0 E3 1E FF 2F E1 04 D0 4D E2 06 8B 2D ED 02 40 A0 E1 F8 25 9F E5")--return 0

--Splunker одна из аналитик которая отправляет сообщения о ваших действиях в игре разрабам и прочим х.з. кому.
original("F0 4B 2D E9 18 B0 8D E2 30 D0 4D E2 00 40 A0 E1 60 06 9F E5 03 50 A0 E1")--0x6C45E4 (void)ForceSplunkLog
replaced("1E FF 2F E1 18 B0 8D E2 30 D0 4D E2 00 40 A0 E1 60 06 9F E5 03 50 A0 E1")--return

--Ещё один Splunker...
--Похоже это перенаправляется в 0x6C45E4?
--original("70 4C 2D E9 10 B0 8D E2 08 D0 4D E2 00 60 A0 E1 74 00 9F E5 02 40 A0 E1")--0x6B5D38 (void)ForceSplunkLog
--replaced("1E FF 2F E1 10 B0 8D E2 08 D0 4D E2 00 60 A0 E1 74 00 9F E5 02 40 A0 E1")--return

--Omniata Analytics отрубаем последнию аналитику!
original("F0 4F 2D E9 1C B0 8D E2 5C D0 4D E2 00 70 A0 E1 9C 05 9F E5 03 90 A0 E1")--0xF3047C (void)Send
replaced("1E FF 2F E1 1C B0 8D E2 5C D0 4D E2 00 70 A0 E1 9C 05 9F E5 03 90 A0 E1")--return

--вот ссылка на доки где разрабы смотрят на сколько забанить игрока
--https://docs.google.com/spreadsheets/d/1ydYd0xoCLy1vDT1Gp2ZEICoIGyYaDA95KhdazUXuvv8
--А вот сам Splunker
--http://54.200.64.69:8089/
--username: developer
--password: sncdev
-- =)

gg.alert("Тест Мод Вкл! (9.920.925)")