import json
import prettytable

from col_lib import *

# Initialize PrettyTable
def ext_table(row_col_names,header,padd) :
	pt = prettytable.PrettyTable(row_col_names)
	pt.set_style(prettytable.UNICODE_LINES)
	pt.xhtml = True
	pt.header = header # Boolean
	pt.left_padding_width = padd
	pt.right_padding_width = padd
	pt.hrules = prettytable.ALL
	pt.vrules = prettytable.ALL
	
	return pt
	
# Convert PrettyTable Object to HTML String
def pt_html(pt_obj) :
	return ansi_escape.sub('', str(pt_obj.get_html_string(format=True, attributes={})))
	
# Convert PrettyTable Object to JSON Dictionary
def pt_json(pt_obj) :
	return json.dumps(pt_obj.get_json_dict(re_pattern=ansi_escape), indent=4)
