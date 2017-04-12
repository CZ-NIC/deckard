"""
Module for contructing equivalence classes of DNS messages

Code taken from http://stackoverflow.com/questions/38924421/is-there-a-standard-way-to-partition-an-interable-into-equivalence-classes-given
"""

import logging

import dns.message
import dns.set


def equivalence_partition(iterable, relation):
    """Partitions a set of objects into equivalence classes

    Args:
        iterable: collection of objects to be partitioned
        relation: equivalence relation. I.e. relation(o1,o2) evaluates to True
            if and only if o1 and o2 are equivalent

    Returns: classes, partitions
        classes: A sequence of sets. Each one is an equivalence class
        partitions: A dictionary mapping objects to equivalence classes
    """
    classes = []
    partitions = {}
    for o in iterable:  # for each object
        # find the class it is in
        found = False
        for c in classes:
            if relation(next(iter(c)), o):  # is it equivalent to this class?
                c.add(o)
                partitions[o] = c
                found = True
                break
        if not found:  # it is in a new class
            classes.append(set([o]))
            partitions[o] = classes[-1]
    return classes, partitions


def equivalence_named(named_iterable, relation):
    """Partitions a set of named objects into equivalence classes

    Args:
        iterable: collection of tuples (name, object) to be partitioned
                  objects are subject of partitioning, names are just metadata
        relation: equivalence relation. I.e. relation(o1,o2) evaluates to True
            if and only if o1 and o2 are equivalent

    Returns: {names: value} dict for containing one value for each equivalent class
    """
    named_classes = []
    for obj_name, obj in named_iterable:  # for each object
        # find the class it is in
        found = False
        for cls_names, cls in named_classes:
            if relation(next(iter(cls)), obj):  # is it equivalent to this class?
                cls.add(obj)
                cls_names.add(obj_name)
                found = True
                break
        if not found:  # it is in a new class
            named_classes.append((dns.set.Set([obj_name]), dns.set.Set([obj])))
    return dict([(frozenset(names), next(iter(objs))) for names, objs in named_classes])


def equivalence_enumeration(iterable, relation):
    """Partitions a set of objects into equivalence classes

    Same as equivalence_partition() but also numbers the classes.

    Args:
        iterable: collection of objects to be partitioned
        relation: equivalence relation. I.e. relation(o1,o2) evaluates to True
            if and only if o1 and o2 are equivalent

    Returns: classes, partitions, ids
        classes: A sequence of sets. Each one is an equivalence class
        partitions: A dictionary mapping objects to equivalence classes
        ids: A dictionary mapping objects to the indices of their equivalence classes
    """
    classes, partitions = equivalence_partition(iterable, relation)
    ids = {}
    for i, c in enumerate(classes):
        for o in c:
            ids[o] = i
    return classes, partitions, ids


def check_equivalence_partition(classes, partitions, relation):
    """Checks that a partition is consistent under the relationship"""
    for o, c in partitions.items():
        for _c in classes:
            assert (o in _c) ^ (_c is not c)
    for c1 in classes:
        for o1 in c1:
            for c2 in classes:
                for o2 in c2:
                    assert (c1 is c2) ^ (not relation(o1, o2))


def test_equivalence_partition():
    def relation(x, y):
        return (x - y) % 4 == 0
    classes, partitions = equivalence_partition(
        range(-3, 5),
        relation
    )
    check_equivalence_partition(classes, partitions, relation)
    for c in classes:
        print(c)
    for o, c in partitions.items():
        print(o, ':', c)


def merge_rrsets(rrsets):
    """Merge multiple RR sets of the matching types into one.
    Args: rrsets
        rrsets: list of RRsets to be merged (e.g. [A, AAAA, A, A, AAAA])
    Returns: rrsets
        rrsets: list of merged RRsets (e.g. [A, AAAA])

    This is not effectient at all but we are operating on small data sets
    so I do not care.
    """
    merged = []
    for origrrs in rrsets:
        for unionrrs in merged:
            if unionrrs.match(origrrs.name, origrrs.rdclass, origrrs.rdtype, origrrs.covers):
                union.update(origrrs)
                continue
        # no matching RR set in merged list
        merged.append(origrrs.copy())
    return merged


def compare_rrsets(x, y):
    """ordering relation based on rdtype"""
    relation, order, nlabels = x.name.fullcompare(y.name)
    if order:
        return order
    else:
        return max(-1, min(1, x.rdtype - y.rdtype))


def compare_dns_messages(m1, m2, merge_rrsets_first=True, sort_rrsets=True):
    """Compare two dns.message.Message instances"""
    assert isinstance(m1, dns.message.Message) or isinstance(m2, dns.message.Message)
    if isinstance(m1, dns.message.Message) != isinstance(m2, dns.message.Message):
        return False
    ignored_attrs = set(['id', 'index', 'time', 'hack_source_ip', 'payload'])
    sections = ['question', 'answer', 'authority', 'additional']
    for m in (m1, m2):
        for section in sections:
            section_list = getattr(m, section)
            if merge_rrsets_first:
                    section_list = merge_rrsets(section_list)
            if sort_rrsets:
                    section_list.sort(cmp=compare_rrsets)
            setattr(m, section, section_list)

    for attr in dir(m1):
        # some attributes are intentionally not compared
        if (callable(getattr(m1, attr)) or
                attr.startswith('_') or
                attr in ignored_attrs):
            continue
        if getattr(m1, attr) != getattr(m2, attr):
            logging.debug('answer attr %s from %s "%s" != answer from %s "%s"',
                          attr,
                          m1.hack_source_ip, getattr(m1, attr),
                          m2.hack_source_ip, getattr(m2, attr))
            return False
    return True
