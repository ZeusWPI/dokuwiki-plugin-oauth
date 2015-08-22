<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Zeus;

/**
 * Class ZeusAdapter
 *
 * @package OAuth\Plugin
 */
class ZeusAdapter extends AbstractAdapter {
    /**
     * Return the scope to request
     *
     * This should return the minimal scope needed for accessing the user's data
     *
     * @return array
     */
    public function getScope() {
        return array(Zeus::SCOPE_READ, Zeus::SCOPE_WRITE);
    }

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $result = $JSON->decode($this->oAuth->request('https://kelder.zeus.ugent.be/oauth/api/current_user?format=json'));

        $data['user'] = $result['username'];
        $data['name'] = $result['username'];
        $data['mail'] = $result['username'] . '@zeus.ugent.be';

        return $data;
    }
}
