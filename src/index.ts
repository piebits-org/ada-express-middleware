import axios from 'axios';
import { Request, Response, NextFunction } from 'express';
import unless from 'express-unless';
import { readFileSync } from 'fs';
import { verify } from 'jsonwebtoken';
import { ADA_PARAMS } from './types';

const supported_version = '020';

const public_key = readFileSync('jwt_ada.key.pub');

export default function ada_middleware({ app_id, fetchuser = false, scope }: ADA_PARAMS) {
  const middleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.headers.authorization;
      if (token) {
        if (fetchuser) {
          const { data } = await axios.get(
            `https://ada.cloud.piebits.org/${supported_version}/userops/fetch/self?scope=${scope}`,
            {
              headers: {
                Authorization: token,
                'x-ada-app-id': app_id,
              },
            },
          );
          req.ada_user = data;
          next();
        } else {
          const token_without_bearer = token.split('Bearer ')[1];
          const data = verify(token_without_bearer, public_key, {
            issuer: 'https://ada.cloud.piebits.org',
            audience: req.ip,
            algorithms: ['RS256'],
          });
          req.ada_user = data as object;
          next();
        }
      } else {
        res.status(400).send('Auth Error: Token Missing');
      }
    } catch {
      res.status(401).send('Auth Error: Invalid Token');
    }
  };

  middleware.unless = unless;

  return middleware;
}
