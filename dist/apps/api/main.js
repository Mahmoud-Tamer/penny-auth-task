/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/api/config.ts":
/***/ ((__unused_webpack_module, exports) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JWT_SECRET = void 0;
exports.JWT_SECRET = (_a = process.env.JWT_SECRET) !== null && _a !== void 0 ? _a : 'secret';


/***/ }),

/***/ "./apps/api/src/app.module.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const typeorm_1 = __webpack_require__("@nestjs/typeorm");
const user_module_1 = __webpack_require__("./apps/api/src/user/user.module.ts");
const auth_module_1 = __webpack_require__("./apps/api/src/auth/auth.module.ts");
const config_1 = __webpack_require__("@nestjs/config");
let AppModule = class AppModule {
};
AppModule = (0, tslib_1.__decorate)([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forRootAsync({
                imports: [config_1.ConfigModule],
                inject: [config_1.ConfigService],
                useFactory: (configService) => (0, tslib_1.__awaiter)(void 0, void 0, void 0, function* () {
                    const isProduction = configService.get('STAGE') === 'prod';
                    return {
                        ssl: isProduction,
                        extra: {
                            ssl: isProduction ? { rejectUnauthorized: false } : null,
                        },
                        type: 'mongodb',
                        autoLoadEntities: true,
                        synchronize: true,
                        host: configService.get('DB_HOST'),
                        port: configService.get('DB_PORT'),
                        username: configService.get('DB_USERNAME'),
                        password: configService.get('DB_PASSWORD'),
                        database: configService.get('DB_DATABASE'),
                    };
                }),
            }),
            user_module_1.UserModule,
            auth_module_1.AuthModule,
        ],
    })
], AppModule);
exports.AppModule = AppModule;


/***/ }),

/***/ "./apps/api/src/auth/auth.controller.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const tslib_1 = __webpack_require__("tslib");
const user_dto_1 = __webpack_require__("./apps/api/src/user/user.dto.ts");
const common_1 = __webpack_require__("@nestjs/common");
const passport_1 = __webpack_require__("@nestjs/passport");
const auth_service_1 = __webpack_require__("./apps/api/src/auth/auth.service.ts");
const jwt_1 = __webpack_require__("@nestjs/jwt");
let AuthController = class AuthController {
    constructor(authService, jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }
    findAll(req) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            try {
                const { authorization } = req.headers;
                const token = authorization.replace('Bearer ', '');
                const userInfo = this.jwtService.decode(token);
                if (new Date().getTime() - new Date(userInfo['signDate']).getTime() >=
                    1000 * 60 * 60 * 8) {
                    throw new common_1.UnauthorizedException('expired token');
                }
            }
            catch (err) { }
            return yield this.authService.findAll();
        });
    }
    register(req, res) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const result = yield this.authService.register(req);
            res.status(result.statusCode).send(result);
        });
    }
    login(req, res) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const result = yield this.authService.login(req);
            res.status(result.statusCode).send(result);
        });
    }
};
(0, tslib_1.__decorate)([
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, common_1.Get)('users'),
    (0, tslib_1.__param)(0, (0, common_1.Request)()),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [Object]),
    (0, tslib_1.__metadata)("design:returntype", typeof (_a = typeof Promise !== "undefined" && Promise) === "function" ? _a : Object)
], AuthController.prototype, "findAll", null);
(0, tslib_1.__decorate)([
    (0, common_1.Post)('signUp'),
    (0, tslib_1.__param)(0, (0, common_1.Body)()),
    (0, tslib_1.__param)(1, (0, common_1.Res)()),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_b = typeof user_dto_1.UserDto !== "undefined" && user_dto_1.UserDto) === "function" ? _b : Object, Object]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], AuthController.prototype, "register", null);
(0, tslib_1.__decorate)([
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('local')),
    (0, common_1.Post)('signIn'),
    (0, tslib_1.__param)(0, (0, common_1.Body)()),
    (0, tslib_1.__param)(0, (0, common_1.Request)()),
    (0, tslib_1.__param)(1, (0, common_1.Res)()),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_c = typeof user_dto_1.UserDto !== "undefined" && user_dto_1.UserDto) === "function" ? _c : Object, Object]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], AuthController.prototype, "login", null);
AuthController = (0, tslib_1.__decorate)([
    (0, common_1.Controller)('auth'),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_d = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _d : Object, typeof (_e = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _e : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./apps/api/src/auth/auth.module.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const tslib_1 = __webpack_require__("tslib");
const auth_controller_1 = __webpack_require__("./apps/api/src/auth/auth.controller.ts");
const common_1 = __webpack_require__("@nestjs/common");
const auth_service_1 = __webpack_require__("./apps/api/src/auth/auth.service.ts");
const user_module_1 = __webpack_require__("./apps/api/src/user/user.module.ts");
const passport_1 = __webpack_require__("@nestjs/passport");
const local_strategy_1 = __webpack_require__("./apps/api/src/auth/local.strategy.ts");
const jwt_1 = __webpack_require__("@nestjs/jwt");
const jwt_strategy_1 = __webpack_require__("./apps/api/src/auth/jwt.strategy.ts");
const config_1 = __webpack_require__("./apps/api/config.ts");
let AuthModule = class AuthModule {
};
AuthModule = (0, tslib_1.__decorate)([
    (0, common_1.Module)({
        imports: [
            passport_1.PassportModule,
            jwt_1.JwtModule.register({
                secret: config_1.JWT_SECRET,
                signOptions: { expiresIn: '7200s' },
            }),
            user_module_1.UserModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, local_strategy_1.LocalStrategy, jwt_strategy_1.JwtStrategy],
        exports: [auth_service_1.AuthService],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./apps/api/src/auth/auth.service.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const user_service_1 = __webpack_require__("./apps/api/src/user/user.service.ts");
const jwt_1 = __webpack_require__("@nestjs/jwt");
const bcrypt = __webpack_require__("bcrypt");
let AuthService = class AuthService {
    constructor(userService, jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }
    findAll() {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return yield this.userService.findAll();
        });
    }
    findOne(username) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return yield this.userService.findUsername(username);
        });
    }
    validateUser(username, pass) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const user = yield this.userService.findUsername(username);
            if (user && bcrypt.compareSync(pass, user.password)) {
                return user;
            }
            return null;
        });
    }
    register(user) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            let userData;
            userData = yield this.userService.findUsername(user.username);
            if (userData) {
                throw new common_1.BadRequestException('This username aleady exists');
            }
            yield this.userService.createUser(user).catch((e) => console.log(e));
            userData = yield this.userService.findUsername(user.username);
            const Token = this.createToken(userData);
            return {
                username: userData.username,
                access_token: Token,
                statusCode: 201,
            };
        });
    }
    login(user) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return this.userService.findUsername(user.username).then((userData) => {
                if (!userData) {
                    throw new common_1.BadRequestException('Check username or password');
                }
                const Token = this.createToken(userData);
                return {
                    id: userData.id,
                    username: userData.username,
                    access_token: Token,
                    statusCode: 200,
                };
            });
        });
    }
    createToken(user) {
        const payload = {
            username: user.username,
            sub: user.id,
            signDate: new Date(),
        };
        return this.jwtService.sign(payload);
    }
};
AuthService = (0, tslib_1.__decorate)([
    (0, common_1.Injectable)(),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_a = typeof user_service_1.UserService !== "undefined" && user_service_1.UserService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./apps/api/src/auth/jwt.strategy.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const passport_1 = __webpack_require__("@nestjs/passport");
const passport_jwt_1 = __webpack_require__("passport-jwt");
const config_1 = __webpack_require__("./apps/api/config.ts");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor() {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: config_1.JWT_SECRET,
        });
    }
    validate(payload) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return { userId: payload.sub, username: payload.username };
        });
    }
};
JwtStrategy = (0, tslib_1.__decorate)([
    (0, common_1.Injectable)(),
    (0, tslib_1.__metadata)("design:paramtypes", [])
], JwtStrategy);
exports.JwtStrategy = JwtStrategy;


/***/ }),

/***/ "./apps/api/src/auth/local.strategy.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LocalStrategy = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const passport_1 = __webpack_require__("@nestjs/passport");
const passport_local_1 = __webpack_require__("passport-local");
const auth_service_1 = __webpack_require__("./apps/api/src/auth/auth.service.ts");
let LocalStrategy = class LocalStrategy extends (0, passport_1.PassportStrategy)(passport_local_1.Strategy) {
    constructor(authService) {
        super();
        this.authService = authService;
    }
    validate(username, password) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const user = yield this.authService.validateUser(username, password);
            if (!user) {
                throw new common_1.ConflictException('check your info');
            }
            return user;
        });
    }
};
LocalStrategy = (0, tslib_1.__decorate)([
    (0, common_1.Injectable)(),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], LocalStrategy);
exports.LocalStrategy = LocalStrategy;


/***/ }),

/***/ "./apps/api/src/entities/abstract-entity.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AbstractEntity = void 0;
const tslib_1 = __webpack_require__("tslib");
const typeorm_1 = __webpack_require__("typeorm");
class AbstractEntity extends typeorm_1.BaseEntity {
}
(0, tslib_1.__decorate)([
    (0, typeorm_1.PrimaryGeneratedColumn)(),
    (0, tslib_1.__metadata)("design:type", Number)
], AbstractEntity.prototype, "id", void 0);
(0, tslib_1.__decorate)([
    (0, typeorm_1.CreateDateColumn)(),
    (0, tslib_1.__metadata)("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], AbstractEntity.prototype, "createdAt", void 0);
(0, tslib_1.__decorate)([
    (0, typeorm_1.UpdateDateColumn)(),
    (0, tslib_1.__metadata)("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], AbstractEntity.prototype, "updatedAt", void 0);
exports.AbstractEntity = AbstractEntity;


/***/ }),

/***/ "./apps/api/src/entities/user.entity.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserEntity = void 0;
const tslib_1 = __webpack_require__("tslib");
const typeorm_1 = __webpack_require__("typeorm");
const bcrypt = __webpack_require__("bcrypt");
const abstract_entity_1 = __webpack_require__("./apps/api/src/entities/abstract-entity.ts");
let UserEntity = class UserEntity extends abstract_entity_1.AbstractEntity {
    hashPassword() {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            this.password = yield bcrypt.hashSync(this.password, 10);
        });
    }
};
(0, tslib_1.__decorate)([
    (0, typeorm_1.Column)(),
    (0, tslib_1.__metadata)("design:type", String)
], UserEntity.prototype, "username", void 0);
(0, tslib_1.__decorate)([
    (0, typeorm_1.Column)(),
    (0, tslib_1.__metadata)("design:type", String)
], UserEntity.prototype, "password", void 0);
(0, tslib_1.__decorate)([
    (0, typeorm_1.BeforeInsert)(),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", []),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserEntity.prototype, "hashPassword", null);
UserEntity = (0, tslib_1.__decorate)([
    (0, typeorm_1.Entity)('user')
], UserEntity);
exports.UserEntity = UserEntity;


/***/ }),

/***/ "./apps/api/src/section/errors.filter.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ExceptionsFilter = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
let ExceptionsFilter = class ExceptionsFilter {
    catch(exception, host) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const ctx = host.switchToHttp();
            const response = ctx.getResponse();
            const request = ctx.getRequest();
            let message = exception.message;
            let isDeepestMessage = false;
            while (!isDeepestMessage) {
                isDeepestMessage = !message.message;
                message = isDeepestMessage ? message : message.message;
            }
            const errorResponse = {
                message: message || 'Request failed',
                status: 1,
            };
            const status = exception instanceof common_1.HttpException ?
                exception.getStatus() :
                common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            response.status(status);
            response.header('Content-Type', 'application/json; charset=utf-8');
            response.send(errorResponse);
        });
    }
};
ExceptionsFilter = (0, tslib_1.__decorate)([
    (0, common_1.Catch)()
], ExceptionsFilter);
exports.ExceptionsFilter = ExceptionsFilter;


/***/ }),

/***/ "./apps/api/src/section/validation.pipe.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidationPipe = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const class_transformer_1 = __webpack_require__("class-transformer");
const class_validator_1 = __webpack_require__("class-validator");
const _ = __webpack_require__("lodash");
let ValidationPipe = class ValidationPipe {
    transform(value, metadata) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const { metatype } = metadata;
            if (!metatype || !this.toValidate(metatype)) {
                return value;
            }
            const object = (0, class_transformer_1.plainToClass)(metatype, value);
            const errors = yield (0, class_validator_1.validate)(object);
            if (errors.length > 0) {
                const errorMessage = _.values(errors[0].constraints)[0];
                throw new common_1.BadRequestException(errorMessage);
            }
            return value;
        });
    }
    toValidate(metatype) {
        const types = [String, Boolean, Number, Array, Object];
        return !types.find(type => metatype === type);
    }
};
ValidationPipe = (0, tslib_1.__decorate)([
    (0, common_1.Injectable)()
], ValidationPipe);
exports.ValidationPipe = ValidationPipe;


/***/ }),

/***/ "./apps/api/src/user/user.dto.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserDto = void 0;
const tslib_1 = __webpack_require__("tslib");
const class_validator_1 = __webpack_require__("class-validator");
const swagger_1 = __webpack_require__("@nestjs/swagger");
class UserDto {
}
(0, tslib_1.__decorate)([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsString)(),
    (0, tslib_1.__metadata)("design:type", String)
], UserDto.prototype, "username", void 0);
(0, tslib_1.__decorate)([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsString)(),
    (0, tslib_1.__metadata)("design:type", String)
], UserDto.prototype, "password", void 0);
exports.UserDto = UserDto;


/***/ }),

/***/ "./apps/api/src/user/user.module.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModule = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const typeorm_1 = __webpack_require__("@nestjs/typeorm");
const user_service_1 = __webpack_require__("./apps/api/src/user/user.service.ts");
const user_entity_1 = __webpack_require__("./apps/api/src/entities/user.entity.ts");
let UserModule = class UserModule {
};
UserModule = (0, tslib_1.__decorate)([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([user_entity_1.UserEntity])],
        providers: [user_service_1.UserService],
        exports: [user_service_1.UserService],
    })
], UserModule);
exports.UserModule = UserModule;


/***/ }),

/***/ "./apps/api/src/user/user.service.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserService = void 0;
const tslib_1 = __webpack_require__("tslib");
const common_1 = __webpack_require__("@nestjs/common");
const typeorm_1 = __webpack_require__("@nestjs/typeorm");
const typeorm_2 = __webpack_require__("typeorm");
const user_entity_1 = __webpack_require__("./apps/api/src/entities/user.entity.ts");
let UserService = class UserService {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    createUser(userDto) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            const user = this.userRepository.create(userDto);
            return yield this.userRepository.save(user);
        });
    }
    findUsername(username) {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return this.userRepository.findOne({ where: { username } });
        });
    }
    findAll() {
        return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
            return yield this.userRepository.find();
        });
    }
};
UserService = (0, tslib_1.__decorate)([
    (0, common_1.Injectable)(),
    (0, tslib_1.__param)(0, (0, typeorm_1.InjectRepository)(user_entity_1.UserEntity)),
    (0, tslib_1.__metadata)("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], UserService);
exports.UserService = UserService;


/***/ }),

/***/ "@nestjs/common":
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@nestjs/swagger":
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),

/***/ "@nestjs/typeorm":
/***/ ((module) => {

module.exports = require("@nestjs/typeorm");

/***/ }),

/***/ "bcrypt":
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "class-transformer":
/***/ ((module) => {

module.exports = require("class-transformer");

/***/ }),

/***/ "class-validator":
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "lodash":
/***/ ((module) => {

module.exports = require("lodash");

/***/ }),

/***/ "passport-jwt":
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ }),

/***/ "passport-local":
/***/ ((module) => {

module.exports = require("passport-local");

/***/ }),

/***/ "tslib":
/***/ ((module) => {

module.exports = require("tslib");

/***/ }),

/***/ "typeorm":
/***/ ((module) => {

module.exports = require("typeorm");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
const core_1 = __webpack_require__("@nestjs/core");
const swagger_1 = __webpack_require__("@nestjs/swagger");
const app_module_1 = __webpack_require__("./apps/api/src/app.module.ts");
const errors_filter_1 = __webpack_require__("./apps/api/src/section/errors.filter.ts");
const validation_pipe_1 = __webpack_require__("./apps/api/src/section/validation.pipe.ts");
function bootstrap() {
    return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
        const app = yield core_1.NestFactory.create(app_module_1.AppModule);
        const options = new swagger_1.DocumentBuilder()
            .setTitle('NestJS-Example')
            .setDescription('The NestJS API description')
            .setVersion('0.0.1')
            .addBearerAuth()
            .build();
        const document = swagger_1.SwaggerModule.createDocument(app, options);
        swagger_1.SwaggerModule.setup('docs', app, document);
        app.useGlobalFilters(new errors_filter_1.ExceptionsFilter());
        app.useGlobalPipes(new validation_pipe_1.ValidationPipe());
        app.enableCors();
        yield app.listen(3000);
    });
}
bootstrap();

})();

var __webpack_export_target__ = exports;
for(var i in __webpack_exports__) __webpack_export_target__[i] = __webpack_exports__[i];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;
//# sourceMappingURL=main.js.map