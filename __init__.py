# -*- coding: utf-8 -*-

import os
import logging
import re
import requests

from pylons.i18n.translation import _

from kallithea.model.db import Repository
from kallithea.lib import helpers as h

log = logging.getLogger(__name__)


# Additional mappings that are not present in the pygments lexers
# used for building stats
# format is {'ext':['Names']} eg. {'py':['Python']} note: there can be
# more than one name for extension
# NOTE: that this will overide any mappings in LANGUAGES_EXTENSIONS_MAP
# build by pygments
EXTRA_MAPPINGS = {}

# additional lexer definitions for custom files
# it's overrides pygments lexers, and uses defined name of lexer to colorize the
# files. Format is {'ext': 'lexer_name'}
# List of lexers can be printed running:
# python -c "import pprint;from pygments import lexers;pprint.pprint([(x[0], x[1]) for x in lexers.get_all_lexers()]);"

EXTRA_LEXERS = {}

#==============================================================================
# WHOOSH INDEX EXTENSIONS
#==============================================================================
# if INDEX_EXTENSIONS is [] it'll use pygments lexers extensions by default.
# To set your own just add to this list extensions to index with content
INDEX_EXTENSIONS = []

# additional extensions for indexing besides the default from pygments
# those gets added to INDEX_EXTENSIONS
EXTRA_INDEX_EXTENSIONS = []

#==============================================================================
# Let's Chat Params
#==============================================================================
LCB_HOSTNAME = os.environ.get('KALLITHEA_LCB_HOSTNAME', 'letschat')
LCB_PORT = os.environ.get('KALLITHEA_LCB_PORT', 5000)
LCB_TOKEN = os.environ.get('KALLITHEA_LCB_TOKEN', '')


def letschat_post_message(room, text):
    url_params = dict(
        host=LCB_HOSTNAME,
        port=LCB_PORT,
        room=room,
    )
    try:
        requests.post('http://{host}:{port}/rooms/{room}/messages'.format(**url_params),
                      data={'text': text},
                      auth=(LCB_TOKEN, 'dummy'),
                      timeout=1.0)
    except requests.exceptions.RequestException:
        return False
    return True

#==============================================================================
# POST CREATE REPOSITORY HOOK
#==============================================================================
# this function will be executed after each repository is created
def _crrepohook(*args, **kwargs):
    """
    Post create repository HOOK
    kwargs available:
     :param repo_name:
     :param repo_type:
     :param description:
     :param private:
     :param created_on:
     :param enable_downloads:
     :param repo_id:
     :param user_id:
     :param enable_statistics:
     :param clone_uri:
     :param fork_id:
     :param group_id:
     :param created_by:
    """
    return 0
CREATE_REPO_HOOK = _crrepohook


#==============================================================================
# PRE CREATE USER HOOK
#==============================================================================
# this function will be executed before each user is created
def _pre_cruserhook(*args, **kwargs):
    """
    Pre create user HOOK, it returns a tuple of bool, reason.
    If bool is False the user creation will be stopped and reason
    will be displayed to the user.
    kwargs available:
    :param username:
    :param password:
    :param email:
    :param firstname:
    :param lastname:
    :param active:
    :param admin:
    :param created_by:
    """
    reason = 'allowed'
    return True, reason
PRE_CREATE_USER_HOOK = _pre_cruserhook

#==============================================================================
# POST CREATE USER HOOK
#==============================================================================
# this function will be executed after each user is created
def _cruserhook(*args, **kwargs):
    """
    Post create user HOOK
    kwargs available:
      :param username:
      :param full_name_or_username:
      :param full_contact:
      :param user_id:
      :param name:
      :param firstname:
      :param short_contact:
      :param admin:
      :param lastname:
      :param ip_addresses:
      :param ldap_dn:
      :param email:
      :param api_key:
      :param last_login:
      :param full_name:
      :param active:
      :param password:
      :param emails:
      :param inherit_default_permissions:
      :param created_by:
    """
    return 0
CREATE_USER_HOOK = _cruserhook


#==============================================================================
# POST DELETE REPOSITORY HOOK
#==============================================================================
# this function will be executed after each repository deletion
def _dlrepohook(*args, **kwargs):
    """
    Post delete repository HOOK
    kwargs available:
     :param repo_name:
     :param repo_type:
     :param description:
     :param private:
     :param created_on:
     :param enable_downloads:
     :param repo_id:
     :param user_id:
     :param enable_statistics:
     :param clone_uri:
     :param fork_id:
     :param group_id:
     :param deleted_by:
     :param deleted_on:
    """
    return 0
DELETE_REPO_HOOK = _dlrepohook


#==============================================================================
# POST DELETE USER HOOK
#==============================================================================
# this function will be executed after each user is deleted
def _dluserhook(*args, **kwargs):
    """
    Post delete user HOOK
    kwargs available:
      :param username:
      :param full_name_or_username:
      :param full_contact:
      :param user_id:
      :param name:
      :param firstname:
      :param short_contact:
      :param admin:
      :param lastname:
      :param ip_addresses:
      :param ldap_dn:
      :param email:
      :param api_key:
      :param last_login:
      :param full_name:
      :param active:
      :param password:
      :param emails:
      :param inherit_default_permissions:
      :param deleted_by:
    """
    return 0
DELETE_USER_HOOK = _dluserhook


#==============================================================================
# POST PUSH HOOK
#==============================================================================

# this function will be executed after each push it's executed after the
# build-in hook that Kallithea uses for logging pushes
def _pushhook(*args, **kwargs):
    """
    Post push hook
    kwargs available:

      :param server_url: url of instance that triggered this hook
      :param config: path to .ini config used
      :param scm: type of VS 'git' or 'hg'
      :param username: name of user who pushed
      :param ip: ip of who pushed
      :param action: push
      :param repository: repository name
      :param pushed_revs: list of pushed revisions
    """
    def _letschat_push_notify(server_url, repository, **kwargs):
        repo = Repository.get_by_repo_name(repository)
        repo_data = repo.get_api_data()
        lcb_room = repo_data.get('ex_letschat_room', '')
        if repo_data.get('ex_letschat_push_notify', '') == 'enabled' and len(lcb_room) > 0:
            from kallithea.lib.vcs.exceptions import RepositoryError
            from kallithea.lib.vcs.backends.git import GitRepository

            texts = []
            git_repo = GitRepository(repo.repo_full_path)
            changeset_url_base = u'{}/{}/changeset'.format(server_url, repository)
            revs = kwargs.get('pushed_revs', [])
            for rev in revs:
                branch_names = []
                if re.match(r'^\w+$', rev):
                    try:
                        out, err = git_repo.run_git_command(['branch', '--contains', rev])
                        branch_names = re.findall(r'[\w\-/]+', out)
                    except RepositoryError as e:
                        return -1
                try:
                    out, err = git_repo.run_git_command(['show', '--name-only', rev])
                    text  = u'Push to {}\n'.format(','.join(branch_names))
                    text += out
                    text += u'\nChangeset URL: {}/{}'.format(changeset_url_base, rev)
                    texts.append(text)
                except RepositoryError as e:
                    return -1
            if len(texts) > 0:
                return letschat_post_message(lcb_room, '\n----\n'.join(texts))
    _letschat_push_notify(**kwargs)
    return 0
PUSH_HOOK = _pushhook


#==============================================================================
# POST PULL HOOK
#==============================================================================

# this function will be executed after each push it's executed after the
# build-in hook that Kallithea uses for logging pulls
def _pullhook(*args, **kwargs):
    """
    Post pull hook
    kwargs available::

      :param server_url: url of instance that triggered this hook
      :param config: path to .ini config used
      :param scm: type of VS 'git' or 'hg'
      :param username: name of user who pulled
      :param ip: ip of who pulled
      :param action: pull
      :param repository: repository name
    """
    return 0
PULL_HOOK = _pullhook


#==============================================================================
# CREATE PULLREQUEST HOOK
#==============================================================================

def _create_pullrequest_hook(*args, **kwargs):
    """
    Create pull request hook
    kwargs available::

      :param pr_title:
      :param pr_description:
      :param pr_created_by:
      :param pr_revisions:
      :param pr_nice_id:
      :param pr_url:
      :param org_ref:
      :param org_repo_name:
      :param org_repo_owner:
      :param other_ref:
      :param other_repo_name:
      :param other_repo_owner:
    """
    def _letschat_create_pullrequest_notify(pr_title,
                                            pr_description,
                                            pr_created_by,
                                            pr_url,
                                            pr_nice_id,
                                            org_repo_name,
                                            org_repo_owner,
                                            other_repo_name,
                                            other_repo_owner,
                                            **kwargs):
        repo = Repository.get_by_repo_name(other_repo_name)
        repo_data = repo.get_api_data()
        lcb_room = repo_data.get('ex_letschat_room', '')
        if len(lcb_room) > 0:
            owners = set((org_repo_owner, other_repo_owner))
            mentions = [u for u in owners if u != pr_created_by]

            text  = u'{} '.format(re.sub(r'([0-9a-z]+)', r'@\1', ' '.join(mentions)))
            text += u'new {pr_nice_id} {pr_title} by {pr_created_by}\n'.format(
                pr_nice_id=pr_nice_id, pr_title=pr_title, pr_created_by=pr_created_by)
            text += u'<<Description>>\n{}\n'.format(pr_description)
            text += u'PR URL: {}'.format(pr_url)
            return letschat_post_message(lcb_room, text)
    _letschat_create_pullrequest_notify(**kwargs)
    return 0
CREATE_PULLREQUEST_HOOK = _create_pullrequest_hook


#==============================================================================
# ADD PULLREQUEST REVIEWER HOOK
#==============================================================================

def _add_pullrequest_reviewer_hook(*args, **kwargs):
    """
    Add pull request reviewer hook
    kwargs available::

      :param pr_title:
      :param pr_description:
      :param pr_created_by:
      :param pr_revisions:
      :param pr_added_reviewers:
      :param pr_nice_id:
      :param pr_url:
      :param org_ref:
      :param other_ref:
      :param other_repo_name:
    """
    def _letschat_add_reviewer_notify(pr_title,
                                      pr_created_by,
                                      pr_added_reviewers,
                                      pr_nice_id,
                                      pr_url,
                                      other_repo_name,
                                      **kwargs):
        repo = Repository.get_by_repo_name(other_repo_name)
        repo_data = repo.get_api_data()
        lcb_room = repo_data.get('ex_letschat_room', '')
        if len(lcb_room) > 0:
            text  = u'{} '.format(re.sub(r'([0-9a-z]+)', r'@\1', ' '.join(pr_added_reviewers)))
            text += u'prease review the {pr_nice_id} by {pr_created_by}: {pr_title}\n'.format(
                pr_nice_id=pr_nice_id, pr_created_by=pr_created_by, pr_title=pr_title)
            text += u'PR URL: {}'.format(pr_url)
            return letschat_post_message(lcb_room, text)
    _letschat_add_reviewer_notify(**kwargs)
    return 0
ADD_PULLREQUEST_REVIEWER_HOOK = _add_pullrequest_reviewer_hook


#==============================================================================
# ADD CHANGESET COMMENT HOOK
#==============================================================================

def _add_changeset_comment_hook(*args, **kwargs):
    """
    Add changeset comment hook
    kwargs available::

      :param comment:
      :param line_no:
      :param status_change:
      :param comment_user:
      :param comment_url:
      :param raw_id:
      :param repo_name:
      :param repo_owner:
      :param branch:
    """
    def _letschat_changeset_comment_notify(comment,
                                           line_no,
                                           comment_user,
                                           comment_url,
                                           raw_id,
                                           repo_name,
                                           repo_owner,
                                           branch,
                                           **kwargs):
        repo = Repository.get_by_repo_name(repo_name)
        repo_data = repo.get_api_data()
        lcb_room = repo_data.get('ex_letschat_room', '')
        if len(lcb_room) > 0:
            text  = u''
            if comment_user != repo_owner:
                text += u'@{} '.format(repo_owner)
            if line_no:
                text += u'add comment to changeset {short_id} on line {line_no} on {branch} by {commented_by}\n'.format(
                    short_id=h.short_id(raw_id), line_no=line_no, branch=branch, commented_by=comment_user)
            else:
                text += u'add comment to changeset {short_id} on {branch} by {commented_by}\n'.format(
                    short_id=h.short_id(raw_id), branch=branch, commented_by=comment_user)
            text += u'<<Comment>>\n{}\n'.format(comment)
            text += u'Comment URL: {}'.format(comment_url)
            return letschat_post_message(lcb_room, text)
    _letschat_changeset_comment_notify(**kwargs)
    return 0
ADD_CHANGESET_COMMENT_HOOK = _add_changeset_comment_hook


#==============================================================================
# ADD PULLREQUEST COMMENT HOOK
#==============================================================================

def _add_pullrequest_comment_hook(*args, **kwargs):
    """
    Add pull request comment hook
    kwargs available::

      :param comment:
      :param line_no:
      :param status_change:
      :param comment_user:
      :param comment_url:
      :param org_ref:
      :param org_repo_owner:
      :param other_repo_name:
      :param other_repo_owner:
      :param pr_title:
      :param pr_nice_id:
      :param pr_owner:
      :param closing_pr:
    """
    def _letschat_pullrequest_comment_notify(comment,
                                             line_no,
                                             comment_user,
                                             comment_url,
                                             org_repo_owner,
                                             other_repo_name,
                                             other_repo_owner,
                                             pr_title,
                                             pr_nice_id,
                                             pr_owner,
                                             **kwargs):
        repo = Repository.get_by_repo_name(other_repo_name)
        repo_data = repo.get_api_data()
        lcb_room = repo_data.get('ex_letschat_room', '')
        if len(lcb_room) > 0:
            owners = set((org_repo_owner, other_repo_owner, pr_owner))
            mentions = [u for u in owners if u != comment_user]

            text  = u'{} '.format(re.sub(r'([0-9a-z]+)', r'@\1', ' '.join(mentions)))
            if line_no:
                text += u'add comment to pullrequest {pr_nice_id} on line {line_no} by {commented_by}: {pr_title}\n'.format(
                    pr_nice_id=pr_nice_id, line_no=line_no, commented_by=comment_user, pr_title=pr_title)
            else:
                text += u'add comment to pullrequest {pr_nice_id} by {commented_by}: {pr_title}\n'.format(
                    pr_nice_id=pr_nice_id, commented_by=comment_user, pr_title=pr_title)
            text += u'<<Comment>>\n{}\n'.format(comment)
            text += u'Comment URL: {}'.format(comment_url)
            return letschat_post_message(lcb_room, text)
    _letschat_pullrequest_comment_notify(**kwargs)
    return 0
ADD_PULLREQUEST_COMMENT_HOOK = _add_pullrequest_comment_hook
