# -*- coding: utf-8 -*-

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

def _make_random_string(length = 5):
    import string
    import random
    return ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])

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
     :param owner_id:
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
     :param owner_id:
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

def _pullrequests_update_merge_test(**kwargs):
    import re
    from kallithea import CONFIG
    from kallithea.lib.vcs.exceptions import RepositoryError
    from kallithea.lib.vcs.backends.git import GitRepository
    from kallithea.model.db import User, Repository, PullRequest, \
            PullRequestReviewers, ChangesetStatus
    from kallithea.model.comment import ChangesetCommentsModel
    from kallithea.model.changeset_status import ChangesetStatusModel
    from kallithea.model.meta import Session

    def _merge_test(**params):
        src_repo_path = '{}/{}'.format(CONFIG.get('base_path', ''), params['repo_name'])
        tmp_repo_path = '/tmp/kallithea/{}'.format(src_repo_path)
        remote_source_branch = 'origin/{pr_source_branch}'.format(**params)
        remote_target_branch = 'origin/{pr_target_branch}'.format(**params)
        local_target_branch = _make_random_string()

        try:
            repo = GitRepository(tmp_repo_path)
        except:
            repo = GitRepository(tmp_repo_path, True, src_repo_path, True)

        def _git(cmds):
            try:
                out, err = repo.run_git_command(cmds)
                return True, out, err
            except RepositoryError as exc:
                err = '\n'.join(exc[0].split('\n')[2:])
                return False, '', err

        _git([ 'fetch', 'origin' ])
        _git([ 'checkout', '-b', local_target_branch, remote_target_branch, ])
        ret, out, err = _git([ 'merge', '--no-commit', remote_source_branch, ])
        if ret:
            comment = u'{} へのマージに成功しました。'.format(params['pr_target_branch'])
            status = ChangesetStatus.STATUS_APPROVED
        else:
            _git([ 'merge', '--abort', ])
            comment = u'{} へのマージに失敗しました。以下のエラーを解消してください。\n\n{}'.format(params['pr_target_branch'], err)
            status = ChangesetStatus.STATUS_REJECTED
        _git([ 'checkout', 'master', ])
        _git([ 'branch', '-D', local_target_branch, ])

        comment = ChangesetCommentsModel().create(
            text = comment,
            repo = pr.org_repo_id,
            author = user.user_id,
            pull_request = pr.pull_request_id,
            status_change = status,
            send_email = False,
        )
        ChangesetStatusModel().set_status(
            pr.org_repo_id,
            status,
            user.user_id,
            comment,
            pull_request = pr.pull_request_id
        )
        Session().commit()

    user = User.guess_instance('kerberos_merge', callback = User.get_by_username)
    branches = { re.sub(r'\w+=>', '', rev) for rev in kwargs['pushed_revs'] }
    for pr in PullRequest.query().filter().all():
        if re.sub(r'branch:([\w\-/]+):\w+', r'\1', pr.other_ref) in branches:
            params = {
                'repo_name': kwargs['repository'],
                'pr_source_branch': re.sub(r'branch:([\w\-/]+):\w+', r'\1', pr.org_ref),
                'pr_target_branch': re.sub(r'branch:([\w\-/]+):\w+', r'\1', pr.other_ref),
            }
            _merge_test(**params)

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
    handlers = [
        _pullrequests_update_merge_test,
    ]
    for handler in handlers:
        handler(**kwargs)
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

def _pullrequest_merge_and_cppcheck(**kwargs):
    import re
    import os.path
    from kallithea import CONFIG
    from kallithea.lib import diffs
    from kallithea.lib.diffs import LimitedDiffContainer
    from kallithea.lib.vcs.backends.git import GitRepository
    from kallithea.lib.vcs.exceptions import ChangesetDoesNotExistError, \
            RepositoryError
    from kallithea.lib.vcs.subprocessio import SubprocessIOChunker
    from kallithea.model.comment import ChangesetCommentsModel
    from kallithea.model.changeset_status import ChangesetStatusModel
    from kallithea.model.db import User, Repository, PullRequest, \
            PullRequestReviewers, ChangesetStatus
    from kallithea.model.meta import Session

    merge_user = User.guess_instance('kerberos_merge',
            callback = User.get_by_username)
    analyze_user = User.guess_instance('kerberos_analyze',
            callback = User.get_by_username)
    pr = PullRequest.guess_instance(kwargs['pr_nice_id'].replace('#', ''))
    prr = PullRequestReviewers(merge_user, pr)
    Session().add(prr)
    prr = PullRequestReviewers(analyze_user, pr)
    Session().add(prr)

    src_repo_path = '{}/{}'.format(CONFIG.get('base_path', ''), kwargs['repo_name'])
    tmp_repo_path = '/tmp/kallithea/{}'.format(src_repo_path)
    remote_source_branch = 'origin/{pr_source_branch}'.format(**kwargs)
    remote_target_branch = 'origin/{pr_target_branch}'.format(**kwargs)
    local_target_branch = _make_random_string()

    try:
        repo = GitRepository(tmp_repo_path)
    except:
        repo = GitRepository(tmp_repo_path, True, src_repo_path, True)

    def _git(cmds):
        try:
            out, err = repo.run_git_command(cmds)
            return True, out, err
        except RepositoryError as exc:
            err = '\n'.join(exc[0].split('\n')[2:])
            return False, '', err

    _git([ 'fetch', 'origin' ])
    _git([ 'rebase', 'origin' ])

    # merge check
    _git([ 'checkout', '-b', local_target_branch, remote_target_branch, ])
    ret, out, err = _git([ 'merge', remote_source_branch, ])
    if ret:
        comment = u'{} へのマージに成功しました。'.format(kwargs['pr_target_branch'])
        status = ChangesetStatus.STATUS_APPROVED
    else:
        _git([ 'merge', '--abort', ])
        comment = u'{} へのマージに失敗しました。以下のエラーを解消してください。\n\n{}'.format(kwargs['pr_target_branch'], err)
        status = ChangesetStatus.STATUS_REJECTED

    comment = ChangesetCommentsModel().create(
        text = comment,
        repo = pr.org_repo_id,
        author = merge_user.user_id,
        pull_request = pr.pull_request_id,
        status_change = status,
    )
    ChangesetStatusModel().set_status(
        pr.org_repo_id,
        status,
        merge_user.user_id,
        comment,
        pull_request = pr.pull_request_id
    )
    if status == ChangesetStatus.STATUS_REJECTED:
        _git([ 'checkout', 'master', ])
        _git([ 'branch', '-D', local_target_branch, ])
        return

    # cppcheck
    try:
        txtdiff = repo.get_diff(kwargs['pr_target_branch'], local_target_branch)
    except ChangesetDoesNotExistError:
        txtdiff = ''
    diff_processor = diffs.DiffProcessor(txtdiff or '', format = 'gitdiff')
    _parsed = diff_processor.prepare()
    files = {}
    for f in _parsed:
        if re.match(r'\.(:?c|cpp|h|hpp)', os.path.splitext(f['filename'])[1]):
            for chunk in f['chunks']:
                lines = [ l['new_lineno'] for l in chunk if l['new_lineno'] > 0 and l['action'] == 'add' ]
                files.update({ f['filename']: lines })

    def _parse_cppcheck_result(message):
        outs = []
        for l in message.split('\n'):
            matches = re.match(r'\[[\w\-/\.]+:(?P<lineno>\d+)\]: \((?P<id>\w+)\) (?P<message>.+)', l)
            if matches is not None:
                outs.append({
                    'lineno': int(matches.group('lineno')),
                    'id': matches.group('id'),
                    'message': matches.group('message'),
                })
        return outs

    status = ChangesetStatus.STATUS_APPROVED
    for k, v in files.items():
        try:
            #cmd = [ 'cppcheck', '--check-config', '--enable=all', '--error-exitcode=1', '{}/{}'.format(tmp_repo_path, k), ]
            cmd = [ 'cppcheck' ]
            #configs = [ '--check-config', '--enable=all', '--error-exitcode=1' ]
            configs = [ '--enable=all', '--error-exitcode=1' ]
            includes = [ '-I/usr/include', '-I/usr/include/x86_64-linux-gnu' ]
            cmd.extend(configs)
            cmd.extend(includes)
            cmd.extend([ '{}/{}'.format(tmp_repo_path, k) ])
            _opts = {
                'env': os.environ,
                'shell': False,
            }
            rc = SubprocessIOChunker(cmd, **_opts)
            print('*** out: {}, err: {} ***'.format(''.join(rc.output), ''.join(rc.error)))
        except (EnvironmentError, OSError) as exc:
            print('*** exc: {} ***'.format(exc))
            results = _parse_cppcheck_result(str(exc))
            for result in results:
                if result['lineno'] in v:
                    ChangesetCommentsModel().create(
                        text = '({id}) {message}'.format(**result),
                        repo = pr.org_repo_id,
                        author = analyze_user.user_id,
                        pull_request = pr.pull_request_id,
                        f_path = k,
                        line_no = 'n{lineno}'.format(**result),
                    )

                    if result['id'] == 'error':
                        status = ChangesetStatus.STATUS_REJECTED

    if status == ChangesetStatus.STATUS_APPROVED:
        comment = u'差分の静的解析で新たなエラーは検出されませんでした。'
    else:
        comment = u'差分の静的解析で新たなエラーが検出されました。'

    comment = ChangesetCommentsModel().create(
        text = comment,
        repo = pr.org_repo_id,
        author = analyze_user.user_id,
        pull_request = pr.pull_request_id,
        status_change = status,
    )
    ChangesetStatusModel().set_status(
        pr.org_repo_id,
        status,
        analyze_user.user_id,
        comment,
        pull_request = pr.pull_request_id
    )

def _create_pullrequest_hook(*args, **kwargs):
    """
    Create pull request hook
    kwargs available::

      :param pr_title:
      :param pr_description:
      :param pr_user_created:
      :param pr_repo_url:
      :param pr_url:
      :param pr_revisions:
      :param repo_name:
      :param repo_owners:
      :param pr_nice_id:
      :param ref:
      :param pr_username:
      :param threading:
    """
    handlers = [
        _pullrequest_merge_and_cppcheck,
    ]
    for handler in handlers:
        handler(**kwargs)
    return 0
CREATE_PULLREQUEST_HOOK = _create_pullrequest_hook


#==============================================================================
# ADD CHANGESET COMMENT HOOK
#==============================================================================

def _heimdall_add_changeset_comment_hook_handler(**kwargs):
    from heimdall.api import GetRepository
    print(kwargs)

def _add_changeset_comment_hook(*args, **kwargs):
    """
    Add changeset comment hook
    kwargs available::

      :param comment:
      :param line_no:
      :param status_change:
      :param comment_user:
      :param target_repo:
      :param comment_url:
      :param raw_id:
      :param message:
      :param repo_name:
      :param repo_owner:
      :param short_id:
      :param branch:
      :param comment_username:
      :param threading:
    """
    handlers = [
        _heimdall_add_changeset_comment_hook_handler,
    ]
    for handler in handlers:
        handler(**kwargs)
    return 0
ADD_CHANGESET_COMMENT_HOOK = _add_changeset_comment_hook


#==============================================================================
# ADD PULLREQUEST COMMENT HOOK
#==============================================================================

def _heimdall_add_pullrequest_comment_hook_handler(**kwargs):
    from heimdall.api import GetRepository
    print(kwargs)

def _add_pullrequest_comment_hook(*args, **kwargs):
    """
    Add pull request comment hook
    kwargs available::

      :param comment:
      :param line_no:
      :param pr_title:
      :param pr_nice_id:
      :param pr_owner:
      :param status_change:
      :param closing_pr:
      :param comment_user:
      :param target_repo:
      :param comment_url:
      :param repo_name:
      :param repo_owners:
      :param ref:
      :param comment_username:
      :param threading:
    """
    handlers = [
        _heimdall_add_pullrequest_comment_hook_handler,
    ]
    for handler in handlers:
        handler(**kwargs)
    return 0
ADD_PULLREQUEST_COMMENT_HOOK = _add_pullrequest_comment_hook


#==============================================================================
# ADD PULLREQUEST REVIEWER HOOK
#==============================================================================

def _add_pullrequest_reviewer_hook(*args, **kwargs):
    """
    Add pull request reviewer hook
    kwargs available::

      :param pr_title:
      :param pr_description:
      :param pr_user_created:
      :param pr_repo_url:
      :param pr_url:
      :param pr_revisions:
      :param repo_name:
      :param repo_owners:
      :param pr_nice_id:
      :param ref:
      :param pr_username:
      :param pr_add_reviewers:
      :param threading:
    """
    print('*** _add_pullrequest_reviewer_hook: {} ***'.format(kwargs))
    return 0
ADD_PULLREQUEST_REVIEWER_HOOK = _add_pullrequest_reviewer_hook
