"""
<Program Name>
  poll_parser

<Purpose>
  Code for parsing the information around a call to poll() as represented by
  strace's format.  posix-omni-parser fails to deal with this correctly so we
  fall back on manually parsing the original line.

	TODO: support for parsing short events attribute?

"""

from .os_dict import POLL_EVENT_TO_INT


def parse_poll_results(syscall_object):
  """
  <Purpose>
    Method for parsing return value of poll() call.
    It determines the return structure of the strace
    line, and grabs its attributes, specifically
    `int fd` and `short revents` attributes.

  <Returns>
    A list of dictionaries representing pollfd atributes
  
  """
  ol = syscall_object.original_line
  ret_struct = ol[ol.rfind('('):]
  ret_struct = ret_struct.strip('()')
  ret_struct = ret_struct.strip('[]')
  pollfds = []
  
  while ret_struct != '':
    closing_curl_index = ret_struct.find('}')
    tmp = ret_struct[:closing_curl_index].lstrip(' ,{').split(', ')
    tmp_dict = {}
    for i in tmp:
      entry = i.split('=')
      tmp_dict[entry[0]] = entry[1]
    pollfds += [tmp_dict]
    ret_struct = ret_struct[closing_curl_index+1:]
  
  for i in pollfds:
    i['fd'] = int(i['fd'])
    i['revents'] = __revents_to_int(i['revents'])

  return pollfds





def parse_poll_input(syscall_object):
  """
  <Purpose>
    Parses the poll() calls input parameters,
    specifically `struct pollfd *fds`

  <Returns>
    A list of all `struct pollfd` attributes for
    each of arguments for the poll() call

  """
  results = syscall_object.args[0].value
  pollfds = []
  for i in results:
    tmp = {}
    i = eval(str(i))
    tmp['fd'] = i[0]
    tmp['events'] = i[1]
    tmp['revents'] = i[2]
    pollfds += [tmp]
  return pollfds





def __revents_to_int(revents):
  """
  <Purpose>
    Helper method that converts revent constants
    into integer representations

  <Returns>
    int representing revents constant

  """
  val = 0
  if '|' in revents:
    revents = revents.split('|')
    for i in revents:
      val = val | POLL_EVENT_TO_INT[i]
  else:
    val = POLL_EVENT_TO_INT[revents]
  return val
