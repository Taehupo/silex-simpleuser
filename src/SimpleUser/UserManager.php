<?php

namespace SimpleUser;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Doctrine\ORM\EntityManager;
use Silex\Application;

class UserManager implements UserProviderInterface
{
    /** @var $entityManager */
    protected $entityManager;

    /** @var \Silex\Application */
    protected $app;

    /** @var EventDispatcher */
    protected $dispatcher;

    /** @var User[] */
    protected $identityMap = array();

    /** @var string */
    protected $userClass = '\SimpleUser\User';

    /** @var bool */
    protected $isUsernameRequired = false;

    /** @var Callable */
    protected $passwordStrengthValidator;

    /** @var string */
    protected $userTableName = 'users';

    /** @var string */
    protected $userCustomFieldsTableName = 'user_custom_fields';

    /** @var array */
    protected $userColumns = array(
        'id' => 'id',
        'email' => 'email',
        'password' => 'password',
        'salt' => 'salt',
        'roles' => 'roles',
        'name' => 'name',
        'time_created' => 'time_created',
        'username' => 'username',
        'isEnabled' => 'isEnabled',
        'confirmationToken' => 'confirmationToken',
        'timePasswordResetRequested' => 'timePasswordResetRequested',
        //Custom Fields
        'user_id' => 'user_id',
        'attribute' => 'attribute',
        'value' => 'value',
    );

    /**
     * Constructor.
     *
     * @param EntityManager $entityManager
     * @param Application $app
     */
    public function __construct(EntityManager $entityManager, Application $app)
    {
        $this->entityManager = $entityManager;
        $this->app = $app;
        $this->dispatcher = $app['dispatcher'];
    }

    // ----- UserProviderInterface -----

    /**
     * Loads the user for the given username or email address.
     *
     * Required by UserProviderInterface.
     *
     * @param string $username The username
     * @return UserInterface
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByUsername($username)
    {
        if (strpos($username, '@') !== false) {
            $user = $this->entityManager->getRepository($this->getUserClass())->findOneBy(array('email' => $username));
            if (!$user) {
                throw new UsernameNotFoundException(sprintf('Email "%s" does not exist.', $username));
            }

            return $user;
        }

        $user = $this->entityManager->getRepository($this->getUserClass())->findOneBy(array('username' => $username));
        if (!$user) {
            throw new UsernameNotFoundException(sprintf('Username "%s" does not exist.', $username));
        }

        return $user;
    }

    /**
     * Refreshes the user for the account interface.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @param UserInterface $user
     * @return UserInterface
     * @throws UnsupportedUserException if the account is not supported
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->getUser($user->getId());
    }

    /**
     * Whether this provider supports the given user class
     *
     * @param string $class
     * @return Boolean
     */
    public function supportsClass($class)
    {
        return ($class === 'SimpleUser\User') || is_subclass_of($class, 'SimpleUser\User');
    }

    // ----- End UserProviderInterface -----

    /**
     * Reconstitute a User object from stored data.
     *
     * @param array $data
     * @return User
     * @throws \RuntimeException if database schema is out of date.
     */
    protected function hydrateUser(array $data)
    {
        // Test for new columns added in v2.0.
        // If they're missing, throw an exception and explain that migration is needed.
        foreach (array(
                     $this->getUserColumns('username'),
                     $this->getUserColumns('isEnabled'),
                     $this->getUserColumns('confirmationToken'),
                     $this->getUserColumns('timePasswordResetRequested')
                 ) as $col) {
            if (!array_key_exists($col, $data)) {
                throw new \RuntimeException('Internal error: database schema appears out of date. See https://github.com/jasongrimes/silex-simpleuser/blob/master/sql/MIGRATION.md');
            }
        }

        $userClass = $this->getUserClass();

        /** @var User $user */
        $user = new $userClass();

        $user->setId($data[$this->getUserColumns('id')]);
        $user->setPassword($data[$this->getUserColumns('password')]);
        $user->setSalt($data[$this->getUserColumns('salt')]);
        $user->setName($data[$this->getUserColumns('name')]);
        if ($roles = explode(',', $data[$this->getUserColumns('roles')])) {
            $user->setRoles($roles);
        }
        $user->setTimeCreated($data[$this->getUserColumns('time_created')]);
        $user->setUsername($data[$this->getUserColumns('username')]);
        $user->setEnabled($data[$this->getUserColumns('isEnabled')]);
        $user->setConfirmationToken($data[$this->getUserColumns('confirmationToken')]);
        $user->setTimePasswordResetRequested($data[$this->getUserColumns('timePasswordResetRequested')]);

        if (!empty($data['customFields'])) {
            $user->setCustomFields($data['customFields']);
        }

        return $user;
    }

    /**
     * Factory method for creating a new User instance.
     *
     * @param string $email
     * @param string $plainPassword
     * @param string $name
     * @param array $roles
     * @return User
     */
    public function createUser($email, $plainPassword, $name = null, $roles = array())
    {

        $userClass = $this->getUserClass();

        $user = new $userClass($email);

        if (!empty($plainPassword)) {
            $this->setUserPassword($user, $plainPassword);
        }

        if ($name !== null) {
            $user->setName($name);
        }
        if (!empty($roles)) {
            $user->setRoles($roles);
        }

        return $user;
    }

    /**
     * Get the password encoder to use for the given user object.
     *
     * @param UserInterface $user
     * @return PasswordEncoderInterface
     */
    protected function getEncoder(UserInterface $user)
    {
        return $this->app['security.encoder_factory']->getEncoder($user);
    }

    /**
     * Encode a plain text password for a given user. Hashes the password with the given user's salt.
     *
     * @param User $user
     * @param string $password A plain text password.
     * @return string An encoded password.
     */
    public function encodeUserPassword(User $user, $password)
    {
        $encoder = $this->getEncoder($user);
        return $encoder->encodePassword($password, $user->getSalt());
    }

    /**
     * Encode a plain text password and set it on the given User object.
     *
     * @param User $user
     * @param string $password A plain text password.
     */
    public function setUserPassword(User $user, $password)
    {
        $user->setPassword($this->encodeUserPassword($user, $password));
    }

    /**
     * Test whether a plain text password is strong enough.
     *
     * Note that controllers must call this explicitly,
     * it's NOT called automatically when setting a password or validating a user.
     *
     * This is just a proxy for the Callable set by setPasswordStrengthValidator().
     * If no password strength validator Callable is explicitly set,
     * by default the only requirement is that the password not be empty.
     *
     * @param User $user
     * @param $password
     * @return string|null An error message if validation fails, null if validation succeeds.
     */
    public function validatePasswordStrength(User $user, $password)
    {
        return call_user_func($this->getPasswordStrengthValidator(), $user, $password);
    }

    /**
     * @return callable
     */
    public function getPasswordStrengthValidator()
    {
        if (!is_callable($this->passwordStrengthValidator)) {
            return function(User $user, $password) {
                if (empty($password)) {
                    return 'Password cannot be empty.';
                }

                return null;
            };
        }

        return $this->passwordStrengthValidator;
    }

    /**
     * Specify a callable to test whether a given password is strong enough.
     *
     * Must take a User instance and a password string as arguments,
     * and return an error string on failure or null on success.
     *
     * @param Callable $callable
     * @throws \InvalidArgumentException
     */
    public function setPasswordStrengthValidator($callable)
    {
        if (!is_callable($callable)) {
            throw new \InvalidArgumentException('Password strength validator must be Callable.');
        }

        $this->passwordStrengthValidator = $callable;
    }

    /**
     * Test whether a given plain text password matches a given User's encoded password.
     *
     * @param User $user
     * @param string $password
     * @return bool
     */
    public function checkUserPassword(User $user, $password)
    {
        return $user->getPassword() === $this->encodeUserPassword($user, $password);
    }

    /**
     * Get a User instance for the currently logged in User, if any.
     *
     * @return UserInterface|null
     */
    public function getCurrentUser()
    {
        if ($this->isLoggedIn()) {
            return $this->app['security']->getToken()->getUser();
        }

        return null;
    }

    /**
     * Test whether the current user is authenticated.
     *
     * @return boolean
     */
    function isLoggedIn()
    {
        $token = $this->app['security']->getToken();
        if (null === $token) {
            return false;
        }

        return $this->app['security']->isGranted('IS_AUTHENTICATED_REMEMBERED');
    }

    /**
     * Get a User instance by its ID.
     *
     * @param int $id
     * @return User|null The User, or null if there is no User with that ID.
     */
    public function getUser($id)
    {
        return $users = $this->entityManager->getRepository($this->getUserClass())->findOneBy(array('id' => $id));
    }

    /**
     * Get a single User instance that matches the given criteria. If more than one User matches, the first result is returned.
     *
     * @param array $criteria
     * @return User|null
     */
    public function findOneBy(array $criteria)
    {
        $users = $this->entityManager->getRepository($this->getUserClass())->findOneBy($criteria);

        if (empty($users)) {
            return null;
        }

        return reset($users);
    }

    /**
     * Find User instances that match the given criteria.
     *
     * @param array $criteria
     * @param array $options An array of the following options (all optional):<pre>
     *      limit (int|array) The maximum number of results to return, or an array of (offset, limit).
     *      order_by (string|array) The name of the column to order by, or an array of column name and direction, ex. array(time_created, DESC)
     * </pre>
     * @return User[] An array of matching User instances, or an empty array if no matching users were found.
     */
    public function findBy(array $criteria = array(), array $options = array()) {
        return $this->entityManager->getRepository($this->getUserClass())->findBy(transformCriteria($criteria));
    }

    protected function transformCriteria(array $criteria) {
        $transformedCriteria = array();
        foreach ($criteria as $key => $val) {
            if ($key == 'customFields') {
                $transformedCriteria[$key] = $val;
            } else {
                $transformedCriteria[$this->getUserColumns($key)] = $val;
            }
        }
        return $transformedCriteria;
    }

    /**
     * Count users that match the given criteria.
     *
     * @param array $criteria
     * @return int The number of users that match the criteria.
     */
    public function findCount(array $criteria = array())
    {

        $criteria = $this->transformCriteria($criteria);
        return count($this->entityManager->getRepository($this->getUserClass())->findBy($criteria));
    }

    /**
     * Insert a new User instance into the database.
     *
     * @param User $user
     *
     * Contains change jasongrimes' library:
     * Problem: the postgres PSO->lastInsertId() requires an additional parameter (which will depend on the db)
     * Solution: Use INSERT INTO RETURNING syntax
     */
    public function insert(User $user)
    {
        $this->dispatcher->dispatch(UserEvents::BEFORE_INSERT, new UserEvent($user));
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        $this->dispatcher->dispatch(UserEvents::AFTER_INSERT, new UserEvent($user));
    }

    /**
     * Update data in the database for an existing user.
     *
     * @param User $user
     */
    public function update(User $user)
    {
        $this->dispatcher->dispatch(UserEvents::BEFORE_UPDATE, new UserEvent($user));
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        $this->dispatcher->dispatch(UserEvents::AFTER_UPDATE, new UserEvent($user));
    }

    /**
     * Delete a User from the database.
     *
     * @param User $user
     */
    public function delete(User $user)
    {
        $this->dispatcher->dispatch(UserEvents::BEFORE_DELETE, new UserEvent($user));

        $this->entityManager->remove($user);
        $this->entityManager->flush();
        $this->dispatcher->dispatch(UserEvents::AFTER_DELETE, new UserEvent($user));
    }

    /**
     * Validate a user object.
     *
     * Invokes User::validate(),
     * and additionally tests that the User's email address and username (if set) are unique across all users.'.
     *
     * @param User $user
     * @return array An array of error messages, or an empty array if the User is valid.
     */
    public function validate(User $user)
    {
        $errors = $user->validate();

        // TODO: Delete these, unique indexes solve this

        // Ensure email address is unique.
        $duplicates = $this->entityManager->getRepository($this->getUserClass())->findBy(array('email' => $user->getEmail()));
        if (!empty($duplicates)) {
            foreach ($duplicates as $dup) {
                if ($user->getId() && $dup->getId() == $user->getId()) {
                    continue;
                }
                $errors['email'] = 'An account with that email address already exists.';
            }
        }

        // Ensure username is unique.
        $duplicates = $this->entityManager->getRepository($this->getUserClass())->findBy(array('username' => $user->getRealUsername()));
        if (!empty($duplicates)) {
            foreach ($duplicates as $dup) {
                if ($user->getId() && $dup->getId() == $user->getId()) {
                    continue;
                }
                $errors['username'] = 'An account with that username already exists.';
            }
        }

        // If username is required, ensure it is set.
        if ($this->isUsernameRequired && !$user->getRealUsername()) {
            $errors['username'] = 'Username is required.';
        }

        return $errors;
    }

    /**
     * Clear User instances from the identity map, so that they can be read again from the database.
     *
     * Call with no arguments to clear the entire identity map.
     * Pass a single user to remove just that user from the identity map.
     *
     * @param mixed $user Either a User instance, an integer user ID, or null.
     */
    public function clearIdentityMap($user = null)
    {
        if ($user === null) {
            $this->identityMap = array();
        } else if ($user instanceof User && array_key_exists($user->getId(), $this->identityMap)) {
            unset($this->identityMap[$user->getId()]);
        } else if (is_numeric($user) && array_key_exists($user, $this->identityMap)) {
            unset($this->identityMap[$user]);
        }
    }

    /**
     * @param string $userClass The class to use for the user model. Must extend SimpleUser\User.
     */
    public function setUserClass($userClass)
    {
        $this->userClass = $userClass;
    }

    /**
     * @return string
     */
    public function getUserClass()
    {
        return $this->userClass;
    }

    public function setUsernameRequired($isRequired)
    {
        $this->isUsernameRequired = (bool) $isRequired;
    }

    public function getUsernameRequired()
    {
        return $this->isUsernameRequired;
    }

    public function setUserTableName($userTableName)
    {
        $this->userTableName = $userTableName;
    }

    public function getUserTableName()
    {
        return $this->userTableName;
    }

    /*
     * Contains change jasongrimes' library:
     * Problem: quoting the columnnames result in trouble when using preparedstatements because
     * ': + columname' becomes ':"columname" instead of :columnname
     * Temporary solution: Dont quote
     * TODO: permanent solution
     */

    public function setUserColumns(array $userColumns){
        $this->userColumns = array_merge($this->userColumns, $userColumns);
    }

    public function getUserColumns($column = ""){
        if ($column == "") return $this->userColumns;
        else return $this->userColumns[$column];
    }

    public function setUserCustomFieldsTableName($userCustomFieldsTableName)
    {
        $this->userCustomFieldsTableName = $userCustomFieldsTableName;
    }

    public function getUserCustomFieldsTableName()
    {
        return $this->userCustomFieldsTableName;
    }

    /**
     * Log in as the given user.
     *
     * Sets the security token for the current request so it will be logged in as the given user.
     *
     * @param User $user
     */
    public function loginAsUser(User $user)
    {
        if (null !== ($current_token = $this->app['security']->getToken())) {
            $providerKey = method_exists($current_token, 'getProviderKey') ? $current_token->getProviderKey() : $current_token->getKey();
            $token = new UsernamePasswordToken($user, null, $providerKey);
            $this->app['security']->setToken($token);

            $this->app['user'] = $user;
        }
    }
}
