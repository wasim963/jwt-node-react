const express = require( 'express' );
const jwt = require( 'jsonwebtoken' );

const app = express();
app.use( express.json() );

const users = [
    {
        id: 1,
        username: 'john',
        password: '12345',
        isAdmin: true
    },
    {
        id: 2,
        username: 'jane',
        password: '12345'
    }
]

const verify = ( req, res, next ) => {
    const authHeader = req.headers.authorization;

    if( authHeader ) {
        const token = authHeader.split(' ')[ 1 ];

        jwt.verify( token, 'mySecretKey', ( err, user ) => {
            if( err ) {
                return res.status( 403 ).json( 'Token is not valid!' );
            } else {
                req.user = user;

                next();
            }
        } )
        
    } else {
        res.status( 401 ).json( 'You are not authenticated!' );
    }
}

const getAccessToken = ( user ) => {
   return jwt.sign( {
       id: user.id,
       isAdmin: user.isAdmin
   }, 'mySecretKey', { expiresIn: '10s' } );
}

const getRefreshToken = ( user ) => {
    return jwt.sign( {
        id: user.id,
        isAdmin: user.isAdmin
    }, 'myRefreshKey' );
}

let refreshTokens = [];

app.post('/api/refresh', ( req, res ) => {
    // Get the refresh token from the user
    const refreshToken = req.body.token;

    // send error if there no token or its invalid
    if( !refreshToken ) {
        return res.status( 401 ).json( 'You are not authenticated!' );
    }
    if( !refreshTokens.includes( refreshToken ) ) {
        return res.status( 403 ).json( 'Refresh token is not valid!' );
    }

    // if everything is okay, create new access token, refresh token and send to the user
    jwt.verify( refreshToken, 'myRefreshKey', ( err, user ) => {
        err && console.log( err );

        refreshTokens = refreshTokens.filter( token => token !== refreshToken );

        const newAccessToken = getAccessToken( user );
        const newRefreshToken = getRefreshToken( user );

        refreshTokens.push( newRefreshToken );

        res.status( 200 ).json( {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        } )
    } )
} )

app.post( '/api/login', ( req, res ) => {
    const { username, password } = req.body;
    const user = users.find( user => {
        return user.username === username && user.password === password;
    } )

    !user && res.status( 400 ).json( "User not found!" );

    const accessToken = getAccessToken( user );
    const refreshToken = getRefreshToken( user );

    refreshTokens.push( refreshToken )

    res.status( 200 ).json( {
        id: user.id,
        isAdmin: user.isAdmin,
        username: user.username,
        accessToken,
        refreshToken
    } );
} );

app.delete( '/api/users/:userId', verify, ( req, res ) => {

    if( req.params.userId == req.user.id || req.user.isAdmin ) {
        res.status( 200 ).json( 'User has been deleted...' );
    } else {
        res.status( 400 ).json( 'You are not allowed to delete this user!' );
    }
} )

app.post( '/api/logout', verify, ( req, res ) => {
    const refreshToken = req.body.token;

    refreshTokens = refreshTokens.filter( token => token !== refreshToken );

    res.status( 200 ).json( 'You have logged out successfully!' );
} )

app.listen('5000', () => {
    console.log('Server started running...');
})