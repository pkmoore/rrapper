"""
<Prgram Name>
  getdents_parser

<Purpose>
  Code for parsing the structure returned by getdents as represented by
  strace's format.  posix-omni-parser fails entirely to deal with these
  structures so we fall back to manually dealing with the original line

"""

# represents different flags for file types
DIRENT_TYPES = {
  'DT_UNKNOWN': 0,
  'DT_FIFO': 1,
  'DT_CHR': 2,
  'DT_DIR': 4,
  'DT_BLK': 6,
  'DT_REG': 8,
  'DT_LNK': 10,
  'DT_SOCK': 12,
  'DT_WHT': 14,
}





def parse_getdents_structure(syscall_object):
  """
  <Purpose>
    Parses a getdents strace call and retrieves directory entries.

  <Returns> 
    if args is not None
      entries:
        A list of parsed directory entries from the getdents object
    else:
      Empty list

  """

  # checks if syscall_object is getdents call
  if 'getdents' not in syscall_object.name:
    raise ValueError('Received argument is not a getdents(64) syscall '
                    'object')

  # return an empty list if no arguments were passed
  if syscall_object.args[1].value == '{}':
    return []

  # parse entry by identifying brackets and seperators
  left_brace = syscall_object.original_line.find('{')
  right_brace = syscall_object.original_line.rfind('}')
  line = syscall_object.original_line[left_brace + 1:right_brace - 1]
  entries = line.split('}, {')
  
  # create a temporary list that adds entries based on comma delimiter,
  # then copy over to actual entries list.
  tmp = []
  for i in entries:
    tmp += [i.split(', ')]
  entries = tmp

  # break apart each entry, and create a dict to represent key and value
  # for each attribute.
  # i.e
  #   d_ino=416894
  #
  tmp = []
  tmp_dict = {}
  for i in entries:
    for j in i:
      s = j.split('=')
      k = s[0].strip('{}')
      v = s[1]
      tmp_dict[k] = v
    tmp += [tmp_dict]
    tmp_dict = {}
  entries = tmp

  # parse attributes for each entry
  for i in entries:
    # retrieve name of file
    i['d_name'] = i['d_name'].lstrip('"').rstrip('"')
    
    # check file type against DIRENT_TYPE
    try:
      i['d_type'] = DIRENT_TYPES[i['d_type']]
    except KeyError:
      raise NotImplementedError('Unsupported d_type: {}'
                                  .format(i['d_type']))

    # identify other attributes and typecast as ints
    i['d_ino'] = int(i['d_ino'])
    i['d_reclen'] = int(i['d_reclen'])
    i['d_off'] = int(i['d_off'])

  return entries
