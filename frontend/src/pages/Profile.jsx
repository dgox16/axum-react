import axios from "axios";
import { useState } from "react";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export const Profile = () => {
	const navigate = useNavigate();
	const [user, setUser] = useState({});
	useEffect(() => {
		const checkLogin = async () => {
			const res = await axios.get("http://localhost:8000/api/users/me", {
				withCredentials: true,
			});
			setUser(res.data.data.user);
		};
		checkLogin();
	}, []);

	const handlerClick = async () => {
		await axios.get("http://localhost:8000/api/auth/logout", {
			withCredentials: true,
		});
		navigate("/login");
	};

	return (
		<div className="flex justify-center items-center mt-16 ">
			{Object.keys(user).length > 0 ? (
				<div className="bg-blue-100 p-8 rounded-lg">
					<h1 className="text-7xl">Nombre: {user.name}</h1>
					<h1 className="text-xl">Email: {user.email}</h1>
					<h1 className="text-xl">Role: {user.role}</h1>
					<h1>id: {user.id}</h1>
					<div className="flex justify-end">
						<button
							type="button"
							onClick={handlerClick}
							className="bg-blue-500 p-2 text-white rounded-md mt-8"
						>
							Cerrar sesion
						</button>
					</div>
				</div>
			) : (
				<div className="">
					<h1 className="mb-5">No hay usuario</h1>
					<a href="/login" className="bg-green-400 p-2 rounded-md mt-6">
						Inicia sesion
					</a>
				</div>
			)}
		</div>
	);
};
