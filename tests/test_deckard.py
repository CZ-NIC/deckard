""" This is unittest file for parse methods in scenario.py """
import os
import shutil
import tempfile

from deckard import create_trust_anchor_files


def test_create_trust_anchor_files():
    """Trust anchors must be into separate files grouped by domain."""
    anchor1a = u'domain1.com.\t3600\tIN\tDS\t11901 7 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    anchor1b = u'domain1.com.\t3600\tIN\tDS\t11902 7 1 1111111111111111111111111111111111111111'
    anchor2a = u'domain2.net.\t3600\tIN\tDS\t59835 7 1 cccccccccccccccccccccccccccccccccccccccc'
    trust_anchors = {'domain1.com': [anchor1a, anchor1b],
                     'domain2.net': [anchor2a]}

    tmpdir = tempfile.mkdtemp()
    try:
        file_names = create_trust_anchor_files(trust_anchors, tmpdir)
        assert sorted(file_names) == sorted('{wd}/ta/{f}'.format(wd=tmpdir, f=f)
                                            for f in [u'domain1.com.key', u'domain2.net.key'])
        for path in file_names:
            with open(path) as ta_file:
                file_name = os.path.basename(path)
                assert file_name[-4:] == '.key'
                domain = file_name[:-4]
                assert ta_file.read() == ''.join(u'{}\n'.format(ta)
                                                 for ta in trust_anchors[domain])
    finally:
        shutil.rmtree(tmpdir)
