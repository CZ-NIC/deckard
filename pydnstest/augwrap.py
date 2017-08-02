#!/usr/bin/python3

# Copyright (C) 2017

import posixpath
import logging
import os
import collections
import sys

from augeas import Augeas

AUGEAS_LOAD_PATH = '/augeas/load/'
AUGEAS_FILES_PATH = '/files/'
AUGEAS_ERROR_PATH = '//error'

log = logging.getLogger('augeas')


def join(*paths):
    """
    join two Augeas tree paths

    FIXME: Beware: // is normalized to /
    """
    norm_paths = [posixpath.normpath(path) for path in paths]
    # first path must be absolute
    assert norm_paths[0][0] == '/'
    new_paths = [norm_paths[0]]
    # relativize all other paths so join works as expected
    for path in norm_paths[1:]:
        if path.startswith('/'):
            path = path[1:]
        new_paths.append(path)
    new_path = posixpath.join(*new_paths)
    log.debug("join: new_path %s", new_path)
    return posixpath.normpath(new_path)


class AugeasWrapper(object):
    """python-augeas higher-level wrapper.

    Load single augeas lens and configuration file.
    Exposes configuration file as AugeasNode object with dict-like interface.

    AugeasWrapper can be used in with statement in the same way as file does.
    """

    def __init__(self, confpath, lens, root=None, loadpath=None,
                 flags=Augeas.NO_MODL_AUTOLOAD | Augeas.NO_LOAD | Augeas.ENABLE_SPAN):
        """Parse configuration file using given lens.

        Params:
            confpath (str): Absolute path to the configuration file
            lens (str): Name of module containing Augeas lens
            root: passed down to original Augeas
            flags: passed down to original Augeas
            loadpath: passed down to original Augeas
            flags: passed down to original Augeas
        """
        log.debug('loadpath: %s', loadpath)
        log.debug('confpath: %s', confpath)
        self._aug = Augeas(root=root, loadpath=loadpath, flags=flags)

        # /augeas/load/{lens}
        aug_load_path = join(AUGEAS_LOAD_PATH, lens)
        # /augeas/load/{lens}/lens = {lens}.lns
        self._aug.set(join(aug_load_path, 'lens'), '%s.lns' % lens)
        # /augeas/load/{lens}/incl[0] = {confpath}
        self._aug.set(join(aug_load_path, 'incl[0]'), confpath)
        self._aug.load()

        errors = self._aug.match(AUGEAS_ERROR_PATH)
        if errors:
            err_msg = '\n'.join(
                ["{}: {}".format(e, self._aug.get(e)) for e in errors]
            )
            raise RuntimeError(err_msg)

        path = join(AUGEAS_FILES_PATH, confpath)
        paths = self._aug.match(path)
        if len(paths) != 1:
            raise ValueError('path %s did not match exactly once' % path)
        self.tree = AugeasNode(self._aug, path)
        self._loaded = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()
        self.close()

    def save(self):
        """Save Augeas tree to its original file."""
        assert self._loaded
        try:
            self._aug.save()
        except IOError as exc:
            log.exception(exc)
            for err_path in self._aug.match('//error'):
                log.error('%s: %s', err_path,
                          self._aug.get(os.path.join(err_path, 'message')))
            raise

    def close(self):
        """
        close Augeas library

        After calling close() the object must not be used anymore.
        """
        assert self._loaded
        self._aug.close()
        del self._aug
        self._loaded = False

    def match(self, path):
        """Yield AugeasNodes matching given expression."""
        assert self._loaded
        assert path
        log.debug('tree match %s', path)
        for matched_path in self._aug.match(path):
            yield AugeasNode(self._aug, matched_path)


class AugeasNode(collections.MutableMapping):
    """One Augeas tree node with dict-like interface."""

    def __init__(self, aug, path):
        """
        Args:
            aug (AugeasWrapper or Augeas): Augeas library instance
            path (str): absolute path in Augeas tree matching single node

        BEWARE: There are no sanity checks of given path for performance reasons.
        """
        assert aug
        assert path
        assert path.startswith('/')
        self._aug = aug
        self._path = path
        self._span = None

    @property
    def path(self):
        """canonical path in Augeas tree, read-only"""
        return self._path

    @property
    def value(self):
        """
        get value of this node in Augeas tree
        """
        value = self._aug.get(self._path)
        log.debug('tree get: %s = %s', self._path, value)
        return value

    @property
    def span(self):
        if self._span is None:
            self._span = "char position %s" % self._aug.span(self._path)[5]
        return self._span

    @property
    def char(self):
        return self._aug.span(self._path)[5]

    @value.setter
    def value(self, value):
        """
        set value of this node in Augeas tree
        """
        log.debug('tree set: %s = %s', self._path, value)
        self._aug.set(self._path, value)

    def __len__(self):
        """
        number of items matching this path

        It is always 1 after __init__() but it may change
        as Augeas tree changes.
        """
        return len(self._aug.match(self._path))

    def __getitem__(self, key):
        if isinstance(key, int):
            # int is a shortcut to write [int]
            target_path = '%s[%s]' % (self._path, key)
        else:
            target_path = self._path + key
        log.debug('tree getitem: target_path %s', target_path)
        paths = self._aug.match(target_path)
        if len(paths) != 1:
            raise KeyError('path %s did not match exactly once' % target_path)
        return AugeasNode(self._aug, target_path)

    def __delitem__(self, key):
        log.debug('tree delitem: %s + %s', self._path, key)
        target_path = self._path + key
        log.debug('tree delitem: target_path %s', target_path)
        self._aug.remove(target_path)

    def __setitem__(self, key, value):
        assert isinstance(value, AugeasNode)
        target_path = self.path + key
        self._aug.copy(value.path, target_path)

    def __iter__(self):
        self_path_len = len(self._path)
        assert self_path_len > 0

        log.debug('tree iter: %s', self._path)
        for new_path in self._aug.match(self._path):
            if len(new_path) == self_path_len:
                yield ''
            else:
                yield new_path[self_path_len - 1:]

    def match(self, subpath):
        """Yield AugeasNodes matching given sub-expression."""
        assert subpath.startswith("/")
        match_path = "%s%s" % (self._path, subpath)
        log.debug('tree match %s: %s', match_path, self._path)
        for matched_path in self._aug.match(match_path):
            yield AugeasNode(self._aug, matched_path)

    def __repr__(self):
        return 'AugeasNode(%s)' % self._path
